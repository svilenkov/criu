#include <inttypes.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <linux/seccomp.h>

#include "log.h"
#include "common/bug.h"
#include "common/xmalloc.h"
#include "common/lock.h"
#include "common/page.h"

#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/asm/syscall-types.h>
#include "debug.h"
#include "uapi/compel/plugins/std/syscall.h"
#include "asm/infect-types.h"
#include "asm/sigframe.h"
#include "infect.h"
#include "ptrace.h"
#include "infect-rpc.h"
#include "infect-priv.h"
#include "infect-util.h"
#include "rpc-pie-priv.h"
#include "infect-util.h"

#define __sys(foo)     foo
#define __sys_err(ret) (-errno)

#include "common/scm.h"
#include "common/scm-code.c"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - (size_t)((struct sockaddr_un *)0)->sun_path)
#endif

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

static int prepare_thread(int pid, struct thread_ctx *ctx);

static inline void close_safe(int *pfd)
{
	if (*pfd > -1) {
		close(*pfd);
		*pfd = -1;
	}
}

static int parse_pid_status(int pid, struct seize_task_status *ss, void *data)
{
	char aux[128];
	FILE *f;

	sprintf(aux, "/proc/%d/status", pid);
	f = fopen(aux, "r");
	if (!f)
		return -1;

	ss->ppid = -1; /* Not needed at this point */
	ss->seccomp_mode = SECCOMP_MODE_DISABLED;

	while (fgets(aux, sizeof(aux), f)) {
		if (!strncmp(aux, "State:", 6)) {
			ss->state = aux[7];
			continue;
		}

		if (!strncmp(aux, "Seccomp:", 8)) {
			if (sscanf(aux + 9, "%d", &ss->seccomp_mode) != 1)
				goto err_parse;

			continue;
		}

		if (!strncmp(aux, "ShdPnd:", 7)) {
			if (sscanf(aux + 7, "%llx", &ss->shdpnd) != 1)
				goto err_parse;

			continue;
		}
		if (!strncmp(aux, "SigPnd:", 7)) {
			if (sscanf(aux + 7, "%llx", &ss->sigpnd) != 1)
				goto err_parse;

			continue;
		}
		if (!strncmp(aux, "SigBlk:", 7)) {
			if (sscanf(aux + 7, "%llx", &ss->sigblk) != 1)
				goto err_parse;

			continue;
		}
	}

	fclose(f);
	return 0;

err_parse:
	fclose(f);
	return -1;
}

int compel_stop_task(int pid)
{
	int ret;
	struct seize_task_status ss = {};

	ret = compel_interrupt_task(pid);
	if (ret == 0)
		ret = compel_wait_task(pid, -1, parse_pid_status, NULL, &ss, NULL);
	return ret;
}

int compel_interrupt_task(int pid)
{
	int ret;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		/*
		 * ptrace API doesn't allow to distinguish
		 * attaching to zombie from other errors.
		 * All errors will be handled in compel_wait_task().
		 */
		pr_warn("Unable to interrupt task: %d (%s)\n", pid, strerror(errno));
		return ret;
	}

	/*
	 * If we SEIZE-d the task stop it before going
	 * and reading its stat from proc. Otherwise task
	 * may die _while_ we're doing it and we'll have
	 * inconsistent seize/state pair.
	 *
	 * If task dies after we seize it but before we
	 * do this interrupt, we'll notice it via proc.
	 */
	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		pr_warn("SEIZE %d: can't interrupt task: %s\n", pid, strerror(errno));
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			pr_perror("Unable to detach from %d", pid);
	}

	return ret;
}

static int skip_sigstop(int pid, int nr_signals)
{
	int i, status, ret;

	/*
	 * 1) SIGSTOP is queued, but isn't handled yet:
	 * SGISTOP can't be blocked, so we need to wait when the kernel
	 * handles this signal.
	 *
	 * Otherwise the process will be stopped immediately after
	 * starting it.
	 *
	 * 2) A seized task was stopped:
	 * PTRACE_SEIZE doesn't affect signal or group stop state.
	 * Currently ptrace reported that task is in stopped state.
	 * We need to start task again, and it will be trapped
	 * immediately, because we sent PTRACE_INTERRUPT to it.
	 */
	for (i = 0; i < nr_signals; i++) {
		ret = ptrace(PTRACE_CONT, pid, 0, 0);
		if (ret) {
			pr_perror("Unable to start process");
			return -1;
		}

		ret = wait4(pid, &status, __WALL, NULL);
		if (ret < 0) {
			pr_perror("SEIZE %d: can't wait task", pid);
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("SEIZE %d: task not stopped after seize\n", pid);
			return -1;
		}
	}
	return 0;
}

#define SIG_MASK(sig) (1ULL << ((sig)-1))

#define SIG_IN_MASK(sig, mask) ((sig) > 0 && (sig) <= SIGMAX && (SIG_MASK(sig) & (mask)))

#define SUPPORTED_STOP_MASK ((1ULL << (SIGSTOP - 1)) | (1ULL << (SIGTSTP - 1)))

static inline int sig_stop(int sig)
{
	return SIG_IN_MASK(sig, SUPPORTED_STOP_MASK);
}

int compel_parse_stop_signo(int pid)
{
	siginfo_t si;

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) < 0) {
		pr_perror("SEIZE %d: can't parse stopped siginfo", pid);
		return -1;
	}

	return si.si_signo;
}

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * interface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */
int compel_wait_task(int pid, int ppid, int (*get_status)(int pid, struct seize_task_status *, void *),
		     void (*free_status)(int pid, struct seize_task_status *, void *), struct seize_task_status *ss,
		     void *data)
{
	siginfo_t si;
	int status, nr_stopsig;
	int ret = 0, ret2, wait_errno = 0;

	/*
	 * It's ugly, but the ptrace API doesn't allow to distinguish
	 * attaching to zombie from other errors. Thus we have to parse
	 * the target's /proc/pid/stat. Sad, but parse whatever else
	 * we might need at that early point.
	 */

try_again:

	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		/*
		 * wait4() can expectedly fail only in a first time
		 * if a task is zombie. If we are here from try_again,
		 * this means that we are tracing this task.
		 *
		 * So here we can be only once in this function.
		 */
		wait_errno = errno;
	}

	ret2 = get_status(pid, ss, data);
	if (ret2)
		goto err;

	if (ret < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
		if (ss->state != 'Z') {
			if (pid == getpid())
				pr_err("The criu itself is within dumped tree.\n");
			else
				pr_err("Unseizable non-zombie %d found, state %c, err %d/%d\n", pid, ss->state, ret,
				       wait_errno);
			return -1;
		}

		if (ret < 0)
			return COMPEL_TASK_ZOMBIE;
		else
			return COMPEL_TASK_DEAD;
	}

	if ((ppid != -1) && (ss->ppid != ppid)) {
		pr_err("Task pid reused while suspending (%d: %d -> %d)\n", pid, ppid, ss->ppid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("SEIZE %d: task not stopped after seize\n", pid);
		goto err;
	}

	ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
	if (ret < 0) {
		pr_perror("SEIZE %d: can't read signfo", pid);
		goto err;
	}

	if (PTRACE_SI_EVENT(si.si_code) != PTRACE_EVENT_STOP) {
		/*
		 * Kernel notifies us about the task being seized received some
		 * event other than the STOP, i.e. -- a signal. Let the task
		 * handle one and repeat.
		 */

		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)si.si_signo)) {
			pr_perror("Can't continue signal handling, aborting");
			goto err;
		}

		if (free_status)
			free_status(pid, ss, data);
		goto try_again;
	}

	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD)) {
		pr_perror("Unable to set PTRACE_O_TRACESYSGOOD for %d", pid);
		return -1;
	}

	if (ss->seccomp_mode != SECCOMP_MODE_DISABLED && ptrace_suspend_seccomp(pid) < 0)
		goto err;

	/*
	 * FIXME(issues/1429): parasite code contains instructions that trigger
	 * SIGTRAP to stop at certain points. In such cases, the kernel sends a
	 * force SIGTRAP that can't be ignored and if it is blocked, the kernel
	 * resets its signal handler to a default one and unblocks it. It means
	 * that if we want to save the origin signal handler, we need to run a
	 * parasite code with the unblocked SIGTRAP.
	 */
	if ((ss->sigpnd | ss->shdpnd) & (1 << (SIGTRAP - 1))) {
		pr_err("Can't dump the %d thread with a pending SIGTRAP.\n", pid);
		goto err;
	}

	nr_stopsig = 0;
	if (SIG_IN_MASK(SIGSTOP, ss->sigpnd))
		nr_stopsig++;
	if (SIG_IN_MASK(SIGSTOP, ss->shdpnd))
		nr_stopsig++;

	if (SIG_IN_MASK(SIGTSTP, ss->sigpnd) && !SIG_IN_MASK(SIGTSTP, ss->sigblk))
		nr_stopsig++;
	if (SIG_IN_MASK(SIGTSTP, ss->shdpnd) && !SIG_IN_MASK(SIGTSTP, ss->sigblk))
		nr_stopsig++;

	if (sig_stop(si.si_signo))
		nr_stopsig++;

	if (nr_stopsig) {
		if (skip_sigstop(pid, nr_stopsig)) {
			/*
			 * Make sure that the task is stopped by a supported stop signal and
			 * send it again to restore task state before criu intervention.
			 */
			if (sig_stop(si.si_signo))
				kill(pid, si.si_signo);
			else
				kill(pid, SIGSTOP);
			goto err;
		}

		return COMPEL_TASK_STOPPED;
	}

	if (si.si_signo == SIGTRAP)
		return COMPEL_TASK_ALIVE;
	else {
		pr_err("SEIZE %d: unsupported stop signal %d\n", pid, si.si_signo);
		goto err;
	}

err:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
		pr_perror("Unable to detach from %d", pid);
	return -1;
}

int compel_resume_task(pid_t pid, int orig_st, int st)
{
	return compel_resume_task_sig(pid, orig_st, st, SIGSTOP);
}

int compel_resume_task_sig(pid_t pid, int orig_st, int st, int stop_signo)
{
	int ret = 0;
	pr_info("compel_resume_task_sig: pid=%d, orig_st=%d, st=%d, stop_signo=%d\n", pid, orig_st, st, stop_signo);

	// siginfo_t siginfo;

    // // Query signal info on stopped task
    // if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) == -1) {
    //     pr_perror("ptrace GETSIGINFO failed");
    //     return -1;
    // }

    // if (siginfo.si_signo == SIGSEGV) {
    //     pr_debug("Task %d stopped due to SIGSEGV\n", pid);
    //     // Handle SIGSEGV case here, e.g., log, decide special action, or skip kill()
    // }

	pr_debug("\tUnseizing %d into %d\n", pid, st);

	if (st == COMPEL_TASK_DEAD) {
		pr_info("%s:%d → COMPEL_TASK_DEAD", __func__, __LINE__);
		kill(pid, SIGKILL);
		return 0;
	} else if (st == COMPEL_TASK_STOPPED) {
		pr_info("%s:%d → COMPEL_TASK_STOPPED", __func__, __LINE__);
		/*
		 * Task might have had STOP in queue. We detected such
		 * guy as COMPEL_TASK_STOPPED, but cleared signal to run
		 * the parasite code. Thus after detach the task will become
		 * running. That said -- STOP everyone regardless of
		 * the initial state.
		 */
		kill(pid, SIGSTOP);
	} else if (st == COMPEL_TASK_ALIVE) {
		pr_info("%s:%d → COMPEL_TASK_ALIVE\n", __func__, __LINE__);
		/*
		 * Same as in the comment above -- there might be a
		 * task with STOP in queue that would get lost after
		 * detach, so stop it again.
		 */
		if (orig_st == COMPEL_TASK_STOPPED) {
			pr_info("%s:%d → COMPEL_TASK_STOPPED\n", __func__, __LINE__);
			/*
			 * Check that stop_signo contain supported stop signal.
			 * If it isn't, then send SIGSTOP. It makes sense in the case
			 * when we get COMPEL_TASK_STOPPED from old image,
			 * where stop_signo was not yet supported.
			 */
			if (sig_stop(stop_signo)) {
				pr_info("%s:%d → NO SIGSTOP\n", __func__, __LINE__);
				kill(pid, stop_signo);
			} else {
				pr_info("%s:%d → SIGSTOP OK]\n", __func__, __LINE__);
				kill(pid, SIGSTOP);
			}
		}
	} else {
		pr_err("Unknown final state %d\n", st);
		ret = -1;
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		pr_perror("Unable to detach from %d", pid);
		return -1;
	}

	return ret;
}

static int gen_parasite_saddr(struct sockaddr_un *saddr, int key)
{
	int sun_len;

	saddr->sun_family = AF_UNIX;
	snprintf(saddr->sun_path, UNIX_PATH_MAX, "X/crtools-pr-%d-%s", key, compel_run_id);

	sun_len = SUN_LEN(saddr);
	*saddr->sun_path = '\0';

	return sun_len;
}

static int prepare_tsock(struct parasite_ctl *ctl, pid_t pid, struct parasite_init_args *args)
{
	int ssock = -1;
	socklen_t sk_len;
	struct sockaddr_un addr;

	pr_info("Putting tsock into pid %d\n", pid);
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid());

	ssock = ctl->ictx.sock;
	sk_len = sizeof(addr);

	if (ssock == -1) {
		pr_err("No socket in ictx\n");
		goto err;
	}

	if (getsockname(ssock, (struct sockaddr *)&addr, &sk_len) < 0) {
		pr_perror("Unable to get name for a socket");
		return -1;
	}

	if (sk_len == sizeof(addr.sun_family)) {
		if (bind(ssock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0) {
			pr_perror("Can't bind socket");
			goto err;
		}

		if (listen(ssock, 1)) {
			pr_perror("Can't listen on transport socket");
			goto err;
		}
	}

	/* Check a case when parasite can't initialize a command socket */
	if (ctl->ictx.flags & INFECT_FAIL_CONNECT)
		args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid() + 1);

	/*
	 * Set to -1 to prevent any accidental misuse. The
	 * only valid user of it is accept_tsock().
	 */
	ctl->tsock = -ssock;
	return 0;
err:
	close_safe(&ssock);
	return -1;
}

static int setup_child_handler(struct parasite_ctl *ctl)
{
	struct sigaction sa = {
		.sa_sigaction = ctl->ictx.child_handler,
		.sa_flags = SA_SIGINFO | SA_RESTART,
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if (sigaction(SIGCHLD, &sa, NULL)) {
		pr_perror("Unable to setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int restore_child_handler(struct parasite_ctl *ctl)
{
	if (sigaction(SIGCHLD, &ctl->ictx.orig_handler, NULL)) {
		pr_perror("Unable to setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack, user_regs_struct_t *regs,
			struct thread_ctx *octx)
{
	k_rtsigset_t block;

	ksigfillset(&block);
	/*
	 * FIXME(issues/1429): SIGTRAP can't be blocked, otherwise its handler
	 * will be reset to the default one.
	 */
	ksigdelset(&block, SIGTRAP);
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &block)) {
		pr_perror("Can't block signals for %d", pid);
		goto err_sig;
	}

	parasite_setup_regs(ip, stack, regs);
	if (ptrace_set_regs(pid, regs)) {
		pr_perror("Can't set registers for %d", pid);
		goto err_regs;
	}

	// pr_info("GCS (TPIDR2_EL0): %p, stack: %p, remote_map: %p, map_length: 0x%lx\n",
	pr_info("parasite_run: About to PTRACE_SETREGS for pid=%d\n", pid);
	pr_info("  -> ip: %p, sp: %p\n", (void *)ip, (void *)regs->sp);
	// for (int i = 0; i < 31; i++)
    // 	pr_info("  x[%02d]: 0x%llx\n", i, regs->regs[i]);

    // todo_read_tpidr2(), regs->sp, ctl->remote_map, ctl->map_length);

	if (ptrace(cmd, pid, NULL, NULL)) {
		pr_perror("Can't run parasite at %d", pid);
		goto err_cont;
	}

	return 0;

err_cont:
	if (ptrace_set_regs(pid, &octx->regs))
		pr_perror("Can't restore regs for %d", pid);
err_regs:
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &octx->sigmask))
		pr_perror("Can't restore sigmask for %d", pid);
err_sig:
	return -1;
}

static int restore_thread_ctx(int pid, struct thread_ctx *ctx, bool restore_ext_regs)
{
	int ret = 0;
	struct user_gcs gcs;
	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };

	pr_debug("Inside %s %s:%d\n", __func__, __FILE__, __LINE__);
	pr_debug("\tOLD SP=%lx IP=%lx\n", (uint64_t) ctx->regs.sp, (uint64_t) ctx->regs.pc);

	if (ptrace_set_regs(pid, &ctx->regs)) {
		pr_perror("Can't restore registers (pid: %d)", pid);
		ret = -1;
	}

	pr_debug("\tNEW SP=%lx IP=%lx\n", (uint64_t) ctx->regs.sp, (uint64_t) ctx->regs.pc);
	pr_debug("after ptrace_set_regs() %s %s:%d\n",  __func__, __FILE__, __LINE__);

	if (restore_ext_regs && compel_set_task_ext_regs(pid, &ctx->ext_regs))
		ret = -1;

	ptrace(PTRACE_GETREGSET, pid, 0x410 , &gcs_iov);
	ctx->ext_regs.gcs = gcs;
	compel_set_task_gcs_regs(pid, &ctx->ext_regs);

	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("Can't block signals");
		ret = -1;
	}

	return ret;
}

/* we run at @regs->ip */
static int parasite_trap(struct parasite_ctl *ctl, pid_t pid, user_regs_struct_t *regs, struct thread_ctx *octx,
			 bool may_use_extended_regs)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("Waited pid mismatch (pid: %d)", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d, status: 0x%x)\n", pid, status);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_perror("Can't get siginfo (pid: %d)", pid);
		goto err;
	}

	if (ptrace_get_regs(pid, regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
		goto err;
	}

	pr_debug("si_add %lx pc %lx sp %lx ctl->ictx.syscall_ip %lx\n", (long)siginfo.si_addr, (long)regs->pc, (long)regs->sp, (long)ctl->ictx.syscall_ip);
	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != ARCH_SI_TRAP) {
		// pr_debug("** delivering signal %d si_code=%d\n", siginfo.si_signo, siginfo.si_code);
		pr_debug("** delivering  signal %d si_code=%d\n, fault address=%p\n", siginfo.si_signo, siginfo.si_code, siginfo.si_addr);

		pr_debug("REG_IP = 0x%llx\n", (unsigned long long) REG_IP(*regs));
		pr_err("Unexpected %d task interruption, aborting\n", pid);

		// *(int*)0 = 0;
		goto err;
	}

	/*
	 * We've reached this point if int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	pr_debug("about to call: restore_thread_ctx %s:%d\n", __FILE__, __LINE__);
	if (restore_thread_ctx(pid, octx, may_use_extended_regs)) {
		ret = -1;
	}

	return ret;
}

void *remote_map_shadow_stack(struct parasite_ctl *ctl, void *addr, size_t length, int flags)
{
	long gcs = 0;
	int err;

	pr_debug("map_shadow_stack: addr=%p len=%zu flags=0x%x\n", addr, length, flags);

	// err = compel_syscall(ctl, __NR_mmap, &map, (unsigned long)addr, length, prot, flags, fd, offset);
	err = compel_syscall(ctl, __NR_map_shadow_stack, &gcs,
	                     0, length, flags,
	                     0, 0, 0); // pad remaining args
	if (err < 0 || gcs == -1)
		gcs = 0;

	pr_debug("✅ remote shadow stack mapped at %p\n", (void *)gcs);

	return (void *)gcs;
}


#define SHADOW_STACK_SET_MARKER (1ULL << 1)
#define SHADOW_STACK_SET_TOKEN (1ULL << 0)


int compel_execute_syscall(struct parasite_ctl *ctl, user_regs_struct_t *regs, const char *code_syscall)
{
	pid_t pid = ctl->rpid;
	int err;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(code_orig, code_syscall, sizeof(code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->ictx.syscall_ip, (void *)code_orig, sizeof(code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		return -1;
	}

	pr_info("parasite_run: pid=%d, syscall_ip=0x%lx, sp=0x%lx, regs=%p, orig=%p\n",
        pid,
        ctl->ictx.syscall_ip,
        (unsigned long)ctl->orig.regs.sp,
        regs,
        &ctl->orig);

	err = parasite_run(pid, PTRACE_CONT, ctl->ictx.syscall_ip, (void *)ctl->orig.regs.sp, regs, &ctl->orig);
	pr_info("CALLING compel_execute_syscall > parasite_trap\n");

	if (!err) {
		pr_info("parasite_trap: ctl=%p, pid=%d, regs=%p, orig=%p, in_syscall=%s\n",
            ctl,
            pid,
            regs,
            &ctl->orig,
            "false");
		err = parasite_trap(ctl, pid, regs, &ctl->orig, false);

		/*
		* Kernel increments PC by 4 after the SVC.
		* Rewind it so the task re-executes the original instruction we
		* restored with ptrace_poke_area() below.
		*/
		// if (!err) {
		// 		regs->pc = ctl->orig.regs.pc;
		// 		// regs->pc = ctl->ictx.syscall_ip;
		// 		if (ptrace_set_regs(pid, regs)) {
		// 				pr_perror("Can't rewind PC (pid %d)", pid);
		// 				err = -1;
		// 		}
		// }

	}
	if (ptrace_poke_area(pid, (void *)code_orig, (void *)ctl->ictx.syscall_ip, sizeof(code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->rpid);
		err = -1;
	}

	return err;
}

int compel_run_at(struct parasite_ctl *ctl, unsigned long ip, user_regs_struct_t *ret_regs)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int ret;

	ret = parasite_run(ctl->rpid, PTRACE_CONT, ip, 0, &regs, &ctl->orig);
	if (!ret)
		ret = parasite_trap(ctl, ctl->rpid, ret_regs ? ret_regs : &regs, &ctl->orig, false);
	return ret;
}

static int accept_tsock(struct parasite_ctl *ctl)
{
	int sock;
	int ask = -ctl->tsock; /* this '-' is explained above */

	sock = accept(ask, NULL, 0);
	if (sock < 0) {
		pr_perror("Can't accept connection to the transport socket");
		close(ask);
		return -1;
	}

	ctl->tsock = sock;
	return 0;
}

static int parasite_init_daemon(struct parasite_ctl *ctl)
{
	struct parasite_init_args *args;
	pid_t pid = ctl->rpid;
	user_regs_struct_t regs;
	struct ctl_msg m = {};

	*ctl->cmd = PARASITE_CMD_INIT_DAEMON;

	args = compel_parasite_args(ctl, struct parasite_init_args);

	args->sigframe = (uintptr_t)ctl->rsigframe;
	args->log_level = compel_log_get_loglevel();
#ifdef ARCH_HAS_LONG_PAGES
	args->page_size = PAGE_SIZE;
#endif

	futex_set(&args->daemon_connected, 0);

	if (prepare_tsock(ctl, pid, args))
		goto err;

	/* after this we can catch parasite errors in chld handler */
	if (setup_child_handler(ctl))
		goto err;

	regs = ctl->orig.regs;
	if (parasite_run(pid, PTRACE_CONT, ctl->parasite_ip, ctl->rstack, &regs, &ctl->orig))
		goto err;

	futex_wait_while_eq(&args->daemon_connected, 0);
	if (futex_get(&args->daemon_connected) != 1) {
		errno = -(int)futex_get(&args->daemon_connected);
		pr_perror("Unable to connect a transport socket");
		goto err;
	}

	if (accept_tsock(ctl) < 0)
		goto err;

	if (compel_util_send_fd(ctl, ctl->ictx.log_fd))
		goto err;

	pr_info("Wait for parasite being daemonized...\n");

	if (parasite_wait_ack(ctl->tsock, PARASITE_CMD_INIT_DAEMON, &m)) {
		pr_err("Can't switch parasite %d to daemon mode %d\n", pid, m.err);
		goto err;
	}

	ctl->sigreturn_addr = (void *)(uintptr_t)args->sigreturn_addr;

	pr_info("parasite_init_daemon: sigreturn_addr=0x%lx sigframe=%ld page_size=0x%lx\n",
		args->sigreturn_addr,
		args->sigframe,
		(unsigned long)__page_size
	);

	ctl->daemonized = true;
	pr_info("Parasite %d has been switched to daemon mode\n", pid);
	return 0;
err:
	return -1;
}

void dump_stack(pid_t pid, uint64_t sp, int slots) {
    uint64_t buf[slots];
    struct iovec local = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct iovec remote = { .iov_base = (void*)sp, .iov_len = sizeof(buf) };

    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n != sizeof(buf)) {
        pr_perror("process_vm_readv victim stack");
        return;
    }

    pr_debug("🪜 Victim stack dump from SP=0x%llx:\n", (unsigned long long)sp);
    for (int i = 0; i < slots; ++i) {
        uint64_t slot_addr = sp + i * 8;
        pr_debug("[%2d] 0x%016llx : 0x%016llx%s\n",
               i,
               (unsigned long long)slot_addr,
               (unsigned long long)buf[i],
               (i == 0) ? " <=== SP" : "");
    }
}

void print_sigframe_table(const struct rt_sigframe *f) {
    const struct cr_sigcontext *sc = RT_SIGFRAME_SIGCONTEXT(f);


    pr_debug("\n+-------------------[ rt_sigframe at: 0x%016" PRIx64 " ]-------------------+\n", (uint64_t)(uintptr_t)f);
    pr_debug("| %-12s | 0x%016" PRIx64 " |\n", "fault_address", (uint64_t)sc->fault_address);
    pr_debug("| %-12s | 0x%016" PRIx64 " |\n", "sp",          (uint64_t)sc->sp);
    pr_debug("| %-12s | 0x%016" PRIx64 " |\n", "pc",          (uint64_t)sc->pc);
    pr_debug("| %-12s | 0x%016" PRIx64 " |\n", "pstate",      (uint64_t)sc->pstate);
    pr_debug("+-----------------------------------------------------+\n");
    pr_debug("| %-12s | %-16s |\n", "Register", "Value");
    for (int i = 0; i < 31; i++) {
        pr_debug("| x%-11d | 0x%016" PRIx64 " |\n", i, (uint64_t)sc->regs[i]);
    }
    pr_debug("+-----------------------------------------------------+\n");
    pr_debug("| %-12s | 0x%016" PRIx64 " |\n", "fp", (uint64_t)f->fp);
    pr_debug("| %-12s | 0x%016" PRIx64 " |\n", "lr", (uint64_t)f->lr);
    pr_debug("+-----------------------------------------------------+\n");

    // Print first few bytes of __reserved (FPU/SIMD context marker)
    pr_debug("| %-12s |", "__reserved[0..15]");
    for (int i = 0; i < 16; ++i)
        pr_debug(" %02x", sc->__reserved[i]);
    pr_debug(" |\n");
    pr_debug("+-----------------------------------------------------+\n");

	// const struct gcs_context *gcs = RT_SIGFRAME_GCS(f);
	// pr_debug("+-------------------[ GCS Context ]-------------------+\n");
	// pr_debug("| %-12s | 0x%016llx |\n", "gcspr", gcs->gcspr);
	// pr_debug("| %-12s | 0x%016llx |\n", "features", gcs->features_enabled);
	// pr_debug("| %-12s | 0x%08x       |\n", "magic", gcs->head.magic);
	// pr_debug("| %-12s | %llu bytes   |\n", "size", gcs->head.size);
	// pr_debug("+-----------------------------------------------------+\n");
}


static int parasite_start_daemon(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->rpid;
	struct infect_ctx *ictx = &ctl->ictx;
	user_fpregs_struct_t ext_regs;

	struct user_gcs gcs;
	struct iovec iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };

	/*
	 * Get task registers before going daemon, since the
	 * compel_get_task_regs() needs to call ptrace on _stopped_ task,
	 * while in daemon it is not such.
	 */

	pr_debug("in function parasite_start_daemon\n");

	if (compel_get_task_regs(pid, &ctl->orig.regs, &ext_regs, ictx->save_regs, ictx->regs_arg, ictx->flags)) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		return -1;
	}

	if (__compel_arch_fetch_thread_area(pid, &ctl->orig)) {
		pr_err("Can't get thread area of %d\n", pid);
		return -1;
	}

	// print_sigframe_table(ctl->sigframe);
	// print_sigframe_table(ctl->rsigframe);

	pr_debug("About to call ictx->make_sigframe\n");
	pr_debug("➡️ Current regs: PC=0x%llx SP=0x%llx x30=0x%llx\n",
		(unsigned long long)ctl->orig.regs.pc,
		(unsigned long long)ctl->orig.regs.sp,
		(unsigned long long)ctl->orig.regs.regs[30]);

	if (ictx->make_sigframe(ictx->regs_arg, ctl->sigframe, ctl->rsigframe, &ctl->orig.sigmask, pid))
		return -1;

	if (parasite_setup_shstk(ctl, &ext_regs))
		return -1;

	if (parasite_setup_gcs(ctl))
		return -1;

	pr_debug("➡️ GCSPR_EL0 after sigframe: 0x%llx", (unsigned long long) gcs.gcspr_el0);
	if (ptrace(PTRACE_GETREGSET, pid, 0x410, &iov)) {
		pr_perror("PTRACE_GETREGSET failed");
		return -1;
	}
	dump_gcs_slots(pid, gcs.gcspr_el0, 0, 0);
	dump_stack(pid, (uint64_t) ctl->orig.regs.sp -16, 12);

	if (parasite_init_daemon(ctl))
		return -1;

	return 0;
}

static int parasite_mmap_exchange(struct parasite_ctl *ctl, unsigned long size, int remote_prot)
{
	int fd;

	ctl->remote_map = remote_mmap(ctl, NULL, size, remote_prot, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", ctl->rpid);
		return -1;
	}

	ctl->map_length = round_up(size, page_size());

	fd = ctl->ictx.open_proc(ctl->rpid, O_RDWR, "map_files/%lx-%lx", (long)ctl->remote_map,
				 (long)ctl->remote_map + ctl->map_length);
	if (fd < 0)
		return -1;

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
	close(fd);

	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't map remote parasite map");
		return -1;
	}

	return 0;
}

static void parasite_memfd_close(struct parasite_ctl *ctl, int fd)
{
	bool compat = !compel_mode_native(ctl);
	long ret;
	int err;

	err = compel_syscall(ctl, __NR(close, compat), &ret, fd, 0, 0, 0, 0, 0);
	if (err || ret)
		pr_err("Can't close memfd\n");
}

static int parasite_memfd_exchange(struct parasite_ctl *ctl, unsigned long size, int remote_prot)
{
	void *where = (void *)ctl->ictx.syscall_ip + BUILTIN_SYSCALL_SIZE;
	bool compat_task = !compel_mode_native(ctl);
	uint8_t orig_code[MEMFD_FNAME_SZ] = MEMFD_FNAME;
	pid_t pid = ctl->rpid;
	long sret = -ENOSYS;
	int ret, fd, lfd, remote_flags;

	if (ctl->ictx.flags & INFECT_NO_MEMFD)
		return 1;

	BUILD_BUG_ON(sizeof(orig_code) < sizeof(long));

	if (ptrace_swap_area(pid, where, (void *)orig_code, sizeof(orig_code))) {
		pr_err("Can't inject memfd args (pid: %d)\n", pid);
		return -1;
	}

	ret = compel_syscall(ctl, __NR(memfd_create, compat_task), &sret, (unsigned long)where, 0, 0, 0, 0, 0);

	if (ptrace_poke_area(pid, orig_code, where, sizeof(orig_code))) {
		fd = (int)sret;
		if (fd >= 0)
			parasite_memfd_close(ctl, fd);
		pr_err("Can't restore memfd args (pid: %d)\n", pid);
		return -1;
	}

	if (ret < 0)
		return ret;

	fd = (int)sret;
	if (fd == -ENOSYS)
		return 1;
	if (fd < 0) {
		errno = -fd;
		pr_perror("Can't create memfd in victim");
		return fd;
	}

	ctl->map_length = round_up(size, page_size());
	lfd = ctl->ictx.open_proc(ctl->rpid, O_RDWR, "fd/%d", fd);
	if (lfd < 0)
		goto err_cure;

	if (ftruncate(lfd, ctl->map_length) < 0) {
		pr_perror("Fail to truncate memfd for parasite");
		goto err_cure;
	}

	remote_flags = MAP_FILE | MAP_SHARED;
	if (ctl->ictx.remote_map_addr){
		remote_flags |= MAP_FIXED_NOREPLACE;
	}
	ctl->remote_map = remote_mmap(ctl, (void *)ctl->ictx.remote_map_addr, size, remote_prot, remote_flags, fd, 0);
	if (!ctl->remote_map) {
		pr_err("Can't rmap memfd for parasite blob\n");
		goto err_curef;
	}

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, lfd, 0);
	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't lmap memfd for parasite blob");
		goto err_curef;
	}

	parasite_memfd_close(ctl, fd);
	close(lfd);

	pr_info("Set up parasite blob using memfd\n");
	return 0;

err_curef:
	close(lfd);
err_cure:
	parasite_memfd_close(ctl, fd);
	return -1;
}

void compel_relocs_apply(void *mem, void *vbase, struct parasite_blob_desc *pbd)
{
	compel_reloc_t *elf_relocs = pbd->hdr.relocs;
	size_t nr_relocs = pbd->hdr.nr_relocs;

	size_t i, j;
	void **got = mem + pbd->hdr.got_off;

	/*
	 * parasite_service() reads the value of __export_parasite_service_args_ptr.
	 * The reason it is set here is that semantically, we are doing a symbol
	 * resolution on parasite_service_args, and it turns out to be relocatable.
	 */
	*(void **)(mem + pbd->hdr.args_ptr_off) = vbase + pbd->hdr.args_off;

#ifdef CONFIG_MIPS
	compel_relocs_apply_mips(mem, vbase, pbd);
#else
	for (i = 0, j = 0; i < nr_relocs; i++) {
		if (elf_relocs[i].type & COMPEL_TYPE_LONG) {
			long *where = mem + elf_relocs[i].offset;

			if (elf_relocs[i].type & COMPEL_TYPE_GOTPCREL) {
				int *value = (int *)where;
				int rel;

				got[j] = vbase + elf_relocs[i].value;
				rel = (unsigned)((void *)&got[j] - (void *)mem) - elf_relocs[i].offset +
				      elf_relocs[i].addend;

				*value = rel;
				j++;
			} else
				*where = elf_relocs[i].value + elf_relocs[i].addend + (unsigned long)vbase;
		} else if (elf_relocs[i].type & COMPEL_TYPE_INT) {
			int *where = (mem + elf_relocs[i].offset);
			*where = elf_relocs[i].value + elf_relocs[i].addend + (unsigned long)vbase;
		} else
			BUG();
	}
#endif
}

long remote_mprotect(struct parasite_ctl *ctl, void *addr, size_t len, int prot)
{
	long ret;
	int err;
	bool compat_task = !user_regs_native(&ctl->orig.regs);

	err = compel_syscall(ctl, __NR(mprotect, compat_task), &ret, (unsigned long)addr, len, prot, 0, 0, 0);
	if (err < 0) {
		pr_err("compel_syscall for mprotect failed\n");
		return -1;
	}
	return ret;
}

static int compel_map_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int ret, remote_prot;

	if (ctl->pblob.hdr.data_off)
		remote_prot = PROT_READ | PROT_EXEC;
	else
		remote_prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	ret = parasite_memfd_exchange(ctl, size, remote_prot);
	if (ret == 1) {
		pr_info("MemFD parasite doesn't work, goto legacy mmap\n");
		ret = parasite_mmap_exchange(ctl, size, remote_prot);
		if (ret)
			return ret;
	}

	if (!ctl->pblob.hdr.data_off)
		return 0;

	ret = remote_mprotect(ctl, ctl->remote_map + ctl->pblob.hdr.data_off, size - ctl->pblob.hdr.data_off,
			      PROT_READ | PROT_WRITE);
	if (ret)
		pr_err("remote_mprotect failed\n");

	return ret;
}

int compel_infect_no_daemon(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size)
{
	int ret;
	unsigned long p, map_exchange_size, parasite_size = 0;

	pr_debug("in function compel_infect_no_daemon\n");

	if (ctl->pblob.parasite_type != COMPEL_BLOB_CHEADER)
		goto err;

	if (ctl->ictx.log_fd < 0)
		goto err;

	if (!arch_can_dump_task(ctl))
		goto err;

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */

	/*
	 * The parasite memory layout is the following:
	 * Low address start first.
	 * The number in parenthesis denotes the size of the section.
	 * The arrow on the right shows the different variables that
	 * corresponds to a given offset.
	 * +------------------------------------------------------+ <--- 0
	 * |   Parasite blob (sizeof(parasite_blob))              |
	 * +------------------------------------------------------+ <--- hdr.bsize
	 *                         align 8
	 * +------------------------------------------------------+ <--- hdr.got_off
	 * |   GOT Table (nr_gotpcrel * sizeof(long))             |
	 * +------------------------------------------------------+ <--- hdr.args_off
	 * |   Args area (args_size)                              |
	 * +------------------------------------------------------+
	 *                         align 64
	 * +------------------------------------------------------+ <--- ctl->rsigframe
	 * |   sigframe (RESTORE_STACK_SIGFRAME)                  |      ctl->sigframe
	 * +------------------------------------------------------+
	 * |   main stack (PARASITE_STACK_SIZE)                   |
	 * +------------------------------------------------------+ <--- ctl->rstack
	 * |   compel_run_in_thread stack (PARASITE_STACK_SIZE)   |
	 * +------------------------------------------------------+ <--- ctl->r_thread_stack
	 *                                                               map_exchange_size
	 */
	parasite_size = ctl->pblob.hdr.args_off;

	ctl->args_size = args_size;
	parasite_size += ctl->args_size;

	/* RESTORE_STACK_SIGFRAME needs a 64 bytes alignment */
	parasite_size = round_up(parasite_size, 64);

	map_exchange_size = parasite_size;
	map_exchange_size += RESTORE_STACK_SIGFRAME + PARASITE_STACK_SIZE;
	if (nr_threads > 1)
		map_exchange_size += PARASITE_STACK_SIZE;

	ret = compel_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);

	ctl->parasite_ip = (unsigned long)(ctl->remote_map + ctl->pblob.hdr.parasite_ip_off);
	ctl->cmd = ctl->local_map + ctl->pblob.hdr.cmd_off;
	ctl->args = ctl->local_map + ctl->pblob.hdr.args_off;

	/*
	 * args must be 4 bytes aligned as we use futexes() on them. It is
	 * already the case, as args follows the GOT table, which is 8 bytes
	 * aligned.
	 */
	if ((unsigned long)ctl->args & (4 - 1)) {
		pr_err("BUG: args are not 4 bytes aligned: %p\n", ctl->args);
		goto err;
	}

	memcpy(ctl->local_map, ctl->pblob.hdr.mem, ctl->pblob.hdr.bsize);
	compel_relocs_apply(ctl->local_map, ctl->remote_map, &ctl->pblob);

	p = parasite_size;

	ctl->rsigframe = ctl->remote_map + p;
	ctl->sigframe = ctl->local_map + p;

	p += RESTORE_STACK_SIGFRAME;
	p += PARASITE_STACK_SIZE;
	ctl->rstack = ctl->remote_map + p - PARASITE_STACK_REDZONE;

	/*
	 * x86-64 ABI requires a 16 bytes aligned stack.
	 * It is already the case as RESTORE_STACK_SIGFRAME is a multiple of
	 * 64, and PARASITE_STACK_SIZE is 0x4000.
	 */
	if ((unsigned long)ctl->rstack & (16 - 1)) {
		pr_err("BUG: stack is not 16 bytes aligned: %p\n", ctl->rstack);
		goto err;
	}

	if (nr_threads > 1) {
		p += PARASITE_STACK_SIZE;
		ctl->r_thread_stack = ctl->remote_map + p - PARASITE_STACK_REDZONE;
	}

	ret = arch_fetch_sas(ctl, ctl->rsigframe);
	if (ret) {
		pr_err("Can't fetch sigaltstack for task %d (ret %d)\n", ctl->rpid, ret);
		goto err;
	}

	return 0;

err:
	return -1;
}

int compel_infect(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size)
{
	if (compel_infect_no_daemon(ctl, nr_threads, args_size)) {
		pr_debug("[compel_infect: FAILED compel_infect_no_daemon");
		return -1;
	}

	if (parasite_start_daemon(ctl)) {
		pr_debug("[compel_infect: FAILED parasite_start_daemon");
		return -1;
	}

	return 0;
}

struct parasite_thread_ctl *compel_prepare_thread(struct parasite_ctl *ctl, int pid)
{
	struct parasite_thread_ctl *tctl;

	tctl = xmalloc(sizeof(*tctl));
	if (tctl) {
		if (prepare_thread(pid, &tctl->th)) {
			xfree(tctl);
			tctl = NULL;
		} else {
			tctl->tid = pid;
			tctl->ctl = ctl;
		}
	}

	return tctl;
}

static int prepare_thread(int pid, struct thread_ctx *ctx)
{
	if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("can't get signal blocking mask for %d", pid);
		return -1;
	}

	if (ptrace_get_regs(pid, &ctx->regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
		return -1;
	}

	return 0;
}

void compel_release_thread(struct parasite_thread_ctl *tctl)
{
	/*
	 * No stuff to cure in thread here, all routines leave the
	 * guy intact (for now)
	 */
	xfree(tctl);
}

struct parasite_ctl *compel_prepare_noctx(int pid)
{
	struct parasite_ctl *ctl = NULL;

	/*
	 * Control block early setup.
	 */
	ctl = xzalloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	ctl->tsock = -1;
	ctl->ictx.log_fd = -1;

	if (prepare_thread(pid, &ctl->orig))
		goto err;

	ctl->rpid = pid;

	BUILD_BUG_ON(PARASITE_START_AREA_MIN < BUILTIN_SYSCALL_SIZE + MEMFD_FNAME_SZ);

	return ctl;

err:
	xfree(ctl);
	return NULL;
}

/*
 * Find first executable VMA that would fit the initial
 * syscall injection.
 */
static unsigned long find_executable_area(int pid)
{
	char aux[128];
	FILE *f;
	unsigned long ret = (unsigned long)MAP_FAILED;

	sprintf(aux, "/proc/%d/maps", pid);
	f = fopen(aux, "r");
	if (!f)
		goto out;

	while (fgets(aux, sizeof(aux), f)) {
		unsigned long start, end;
		char *f;

		start = strtoul(aux, &f, 16);
		end = strtoul(f + 1, &f, 16);

		/* f now points at " rwx" (yes, with space) part */
		if (f[3] == 'x') {
			BUG_ON(end - start < PARASITE_START_AREA_MIN);
			ret = start;
			break;
		}
	}

	fclose(f);
out:
	return ret;
}

/*
 * This routine is to create PF_UNIX/SOCK_SEQPACKET socket
 * in the target net namespace
 */
static int make_sock_for(int pid)
{
	int ret, mfd, fd, sk = -1;
	char p[32];

	pr_debug("Preparing seqsk for %d\n", pid);

	sprintf(p, "/proc/%d/ns/net", pid);
	fd = open(p, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %p", p);
		goto out;
	}

	mfd = open("/proc/self/ns/net", O_RDONLY);
	if (mfd < 0) {
		pr_perror("Can't open self netns");
		goto out_c;
	}

	if (setns(fd, CLONE_NEWNET)) {
		pr_perror("Can't setup target netns");
		goto out_cm;
	}

	sk = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if (sk < 0)
		pr_perror("Can't create seqsk");

	ret = setns(mfd, CLONE_NEWNET);
	if (ret) {
		pr_perror("Can't restore former netns");
		if (sk >= 0)
			close(sk);
		sk = -1;
	}
out_cm:
	close(mfd);
out_c:
	close(fd);
out:
	return sk;
}

static int simple_open_proc(int pid, int mode, const char *fmt, ...)
{
	int l;
	char path[128];
	va_list args;

	l = sprintf(path, "/proc/%d/", pid);

	va_start(args, fmt);
	vsnprintf(path + l, sizeof(path) - l, fmt, args);
	va_end(args);

	return open(path, mode);
}

static void handle_sigchld(int signal, siginfo_t *siginfo, void *data)
{
	int pid, status;

	pid = waitpid(-1, &status, WNOHANG);
	if (pid <= 0)
		return;

	pr_err("si_code=%d si_pid=%d si_status=%d\n", siginfo->si_code, siginfo->si_pid, siginfo->si_status);

	if (WIFEXITED(status))
		pr_err("%d exited with %d unexpectedly\n", pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		pr_err("%d was killed by %d unexpectedly: %s\n", pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
	else if (WIFSTOPPED(status))
		pr_err("%d was stopped by %d unexpectedly\n", pid, WSTOPSIG(status));

	/* FIXME Should we exit? */
	/* exit(1); */
}

struct plain_regs_struct {
	user_regs_struct_t regs;
	user_fpregs_struct_t fpregs;
};

static int save_regs_plain(pid_t pid, void *to, user_regs_struct_t *r, user_fpregs_struct_t *f)
{
	struct plain_regs_struct *prs = to;

	prs->regs = *r;
	prs->fpregs = *f;

	return 0;
}


// void dump_sigframe(void *ptr, size_t len) {
//     unsigned char *p = ptr;
//     printf("Sigframe dump (%zu bytes at %p):\n", len, ptr);
//     for (size_t i = 0; i < len; i++) {
//         printf("%02x ", p[i]);
//         if ((i+1) % 16 == 0) puts("");
//     }
//     puts("");
// }

static int make_sigframe_plain(void *from, struct rt_sigframe *f, struct rt_sigframe *rtf, k_rtsigset_t *b, pid_t pid)

{
	struct plain_regs_struct *prs = from;
	pr_debug("\t[make_sigframe_plain] >");
	pr_debug("PID: %d", pid);

	/*
	 * Make sure it's zeroified.
	 */
	memset(f, 0, sizeof(*f));

	pr_debug("before sigreturn_prep_regs_plain()");
	if (sigreturn_prep_regs_plain(f, &prs->regs, &prs->fpregs))
	return -1;

	if (b) {
		pr_debug("about to call rt_sigframe_copy_sigset()");
		rt_sigframe_copy_sigset(f, b);
	}

	if (RT_SIGFRAME_HAS_FPU(f)) {
		pr_debug("about to call sigreturn_prep_fpu_frame_plain()");
		if (sigreturn_prep_fpu_frame_plain(f, rtf)) {
			pr_debug("ERROR in call sigreturn_prep_fpu_frame_plain()");
			return -1;
		}
	}

	/*
	 * FIXME What about sas?
	 * setup_sas(sigframe, core->thread_core->sas);
	 */
	print_sigframe_table(f);

	return 0;
}

struct parasite_ctl *compel_prepare(int pid)
{
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;

	pr_debug("compel_prepare(%d)", pid);

	ctl = compel_prepare_noctx(pid);
	if (ctl == NULL)
		goto out;

	ictx = &ctl->ictx;
	ictx->task_size = compel_task_size();
	ictx->open_proc = simple_open_proc;
	ictx->syscall_ip = find_executable_area(pid);
	ictx->child_handler = handle_sigchld;
	sigaction(SIGCHLD, NULL, &ictx->orig_handler);

	ictx->save_regs = save_regs_plain;
	ictx->make_sigframe = make_sigframe_plain;

	ictx->regs_arg = xmalloc(sizeof(struct plain_regs_struct));
	if (ictx->regs_arg == NULL)
		goto err;

	if (ictx->syscall_ip == (unsigned long)MAP_FAILED)
		goto err;
	ictx->sock = make_sock_for(pid);
	if (ictx->sock < 0)
		goto err;

out:
	return ctl;

err:
	xfree(ictx->regs_arg);
	xfree(ctl);
	ctl = NULL;
	goto out;
}

static bool task_in_parasite(struct parasite_ctl *ctl, user_regs_struct_t *regs)
{
	void *addr = (void *)REG_IP(*regs);
	return addr >= ctl->remote_map && addr < ctl->remote_map + ctl->map_length;
}

void dump_mem_via_dd(pid_t pid, unsigned long pc) {
    char cmd[256];
    FILE *fp;
    char line[256];
	unsigned long offset;
    unsigned long base = pc - 32;
	char rest[200];

    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=1 skip=%lu count=64 of=/tmp/memchunk.bin 2>/dev/null && "
        "objdump -D -b binary -m aarch64 /tmp/memchunk.bin",
        pid, base);

    fp = popen(cmd, "r");
    if (!fp) {
        perror("popen failed");
        return;
    }

    pr_debug("===== dd | objdump output =====\n");
    while (fgets(line, sizeof(line), fp)) {
        // remove trailing newline
        line[strcspn(line, "\n")] = '\0';

        // try to parse objdump line: "   0:   d4000001        svc     #0x0"

        if (sscanf(line, " %lx: %[^\n]", &offset, rest) == 2) {
            pr_debug("0x%lx:\t%s\n", base + offset, rest);
        } else {
            // non-instruction line, just print as-is
            pr_debug("%s\n", line);
        }
    }
    pr_debug("===============================\n");

    pclose(fp);
}

static void dump_proc_maps(pid_t pid, bool smaps) {
	char path[64];
	FILE *fp;
	char line[512];

	const char *fname = smaps ? "smaps" : "maps";

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, fname);

	fp = fopen(path, "r");
	if (!fp) {
		pr_err("Failed to open %s\n", path);
		return;
	}
	pr_debug("===== /proc/%d/%s =====\n", pid, fname);

	while (fgets(line, sizeof(line), fp)) {
		// Remove potential trailing newline
		line[strcspn(line, "\n")] = 0;
		pr_debug("%s\n", line);
	}

	// dd if=/proc/<pid>/mem bs=1 skip=<PC> count=16 | hexdump -C

	fclose(fp);
	pr_debug("=========================\n");
}


static int parasite_fini_seized(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->rpid;
	user_regs_struct_t regs;
	int status, ret = 0;
	// void* gcs;
	// struct iovec iov;

	struct user_gcs g;
	struct iovec gcs_iov = { .iov_base = &g, .iov_len = sizeof(g) };
	uint64_t expected_cap;

	unsigned long sa_restorer = ctl->parasite_ip;

	/* stop getting chld from parasite -- we're about to step-by-step it */
	pr_debug("About to call restore_child_handler in %s:%d#%s\n", __FILE__, __LINE__, __func__);
	if (restore_child_handler(ctl))
		return -1;

	/* Start to trace syscalls for each thread */
	pr_debug("About to call ptrace(PTRACE_INTERRUPT for each thread in %s:%d#%s\n", __FILE__, __LINE__, __func__);
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
		pr_perror("Unable to interrupt the process");
		return -1;
	}

	pr_debug("Waiting for %d to trap\n", pid);
	// pr_debug("About to call wait4(%d) for each thread in %s:%d#%s\n", pid, __FILE__, __LINE__, __func__);
	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("Waited pid mismatch (pid: %d)", pid);
		return -1;
	}

	pr_debug("Daemon %d exited trapping\n", pid);
	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d, status: 0x%x)\n", pid, status);
		return -1;
	}

	pr_debug("About to call ptrace_get_regs for each thread in %s:%d#%s\n", __FILE__, __LINE__, __func__);
	ret = ptrace_get_regs(pid, &regs);
	if (ret) {
		pr_perror("Unable to get registers");
		return -1;
	}

	pr_debug("About to call task_in_parasite for each thread in %s:%d#%s\n", __FILE__, __LINE__, __func__);
	if (!task_in_parasite(ctl, &regs)) {
		pr_err("The task is not in parasite code\n");
		return -1;
	}

	pr_debug("About to call compel_rpc_call(PARASITE_CMD_FINI for each thread in %s:%d#%s\n", __FILE__, __LINE__, __func__);
	ret = compel_rpc_call(PARASITE_CMD_FINI, ctl);
	close_safe(&ctl->tsock);
	if (ret)
		return -1;

	/* Go to sigreturn as closer as we can */
	pr_debug("compel_stop_pie(%d, %p for each thread in %s:%d#%s\n", pid, ctl->sigreturn_addr, __FILE__, __LINE__, __func__);
	ret = compel_stop_pie(pid, ctl->sigreturn_addr, ctl->ictx.flags & INFECT_NO_BREAKPOINTS);
	if (ret < 0)
		return ret;

	sleep(1);
	if (ptrace(PTRACE_GETREGSET, pid, 0x410 /* NT_ARM_GCS */, &gcs_iov) != 0) {
        pr_perror("GCS state not available for %d\n", pid);
        return -1;
    }

	pr_info("[DBG-pre-sigreturn] pid=%d PC=0x%llx SP=0x%llx GCSPR_EL0=0x%llx\n",
			ctl->rpid,
			(unsigned long long)ctl->orig.regs.pc,
			(unsigned long long)ctl->orig.regs.sp,
			(unsigned long long)g.gcspr_el0);

	expected_cap = 0xfffff7def000;

	dump_gcs_slots(ctl->rpid, g.gcspr_el0, 0, expected_cap);

	// ptrace(PTRACE_POKEDATA, pid, (void*)g.gcspr_el0, 0xfffff7def000);
	// sa_restorer = 0xfffff7e795dc;
	// ptrace(PTRACE_POKEDATA, pid, (void*)g.gcspr_el0, 0xfffff7def000);
	pr_debug("ctl->parasite_ip: %lx\n",sa_restorer);
	dump_stack(pid, (uint64_t) regs.sp, 8);
	// ptrace(PTRACE_POKEDATA, pid, (void*)g.gcspr_el0 - 8, sa_restorer);

	// g.gcspr_el0 = g.gcspr_el0 + sizeof(uint64_t);

	// iov.iov_base = &g;
	// iov.iov_len = sizeof(*&g);
	// if(ptrace(PTRACE_SETREGSET, pid, 0x410, &iov)) {
	// 	pr_perror("PTRACE_SETREGSET FIALED");
	// 	return -1;
	// }

	// ptrace(PTRACE_POKEDATA, pid, (void*)g.gcspr_el0-8, 0xDEADBEEFDEADBEEC);
	// ptrace(PTRACE_POKEDATA, pid, (void*)g.gcspr_el0-16, 0xDEADBEEFDEADBEED);
	// ptrace(PTRACE_POKEDATA, pid, (void*)g.gcspr_el0+16, 0xDEADBEEFDEADBEE);

	pr_info("➡️ Waiting for task to enter & exit syscall: %d\n", __NR_rt_sigreturn);

	pr_debug("DUMPING /proc/%d/maps 💩 compel_stop_on_syscall\n", pid);
	dump_proc_maps(pid, false);

	pr_debug("DUMPING /proc/%d/smaps 🔓 compel_stop_on_syscall\n", pid);
	dump_proc_maps(pid, true);

	pr_debug("Dumping mem for ctl->orig.regs.pc=%llx\n", ctl->orig.regs.pc);
	dump_mem_via_dd(pid, ctl->orig.regs.pc);

	pr_debug("Dumping mem for regs.pc=%llx\n", regs.pc);
	dump_mem_via_dd(pid, regs.pc);

	if (compel_stop_on_syscall(1, __NR(rt_sigreturn, 0), __NR(rt_sigreturn, 1))) {
		pr_err("❌ compel_stop_on_syscall() failed while waiting for rt_sigreturn\n");
		return -1;
	}
	dump_gcs_slots(pid, g.gcspr_el0, 0, expected_cap);
	// dump_stack(pid, (uint64_t) ctl->orig.regs.sp, 8);
	// dump_stack(pid, (uint64_t) ctl->orig.regs.regs[2], 8);
	// dump_stack(pid, (uint64_t) ctl->rstack, 8);

	pr_info("[POST-sigreturn] pid=%d PC=0x%llx x30=0x%llx SP=0x%llx GCSPR_EL0=0x%llx\n",
			ctl->rpid,
			(unsigned long long)ctl->orig.regs.pc,
			(unsigned long long)ctl->orig.regs.regs[30],
			(unsigned long long)ctl->orig.regs.sp,
			(unsigned long long)g.gcspr_el0);
	pr_info("✅ Task completed rt_sigreturn syscall (trapped on exit)\n");

	/*
	 * All signals are unblocked now. The kernel notifies about leaving
	 * syscall before starting to deliver signals. All parasite code are
	 * executed with blocked signals, so we can sefly unmap a parasite blob.
	 */

	return 0;
}

int compel_start_daemon(struct parasite_ctl *ctl)
{
	return parasite_start_daemon(ctl);
}

int compel_stop_daemon(struct parasite_ctl *ctl)
{
	if (ctl->daemonized) {
		/*
		 * Looks like a previous attempt failed, we should do
		 * nothing in this case. parasite will try to cure itself.
		 */
		if (ctl->tsock < 0)
			return -1;

		pr_debug("About to call parasite_fini_seized in %s:%d#%s\n", __FILE__, __LINE__, __func__);
		if (parasite_fini_seized(ctl)) {
			close_safe(&ctl->tsock);
			return -1;
		}
	}

	ctl->daemonized = false;

	return 0;
}

int compel_cure_remote(struct parasite_ctl *ctl)
{
	long ret;
	int err;
	struct user_gcs gcs;
	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };
	// uint64_t test_value;

	pr_info("Curing remote (%s) \n", __FILE__);

	if (compel_stop_daemon(ctl))
		return -1;

	pr_info("compel_stop_daemon ✅\n");
	print_callstack();
	dump_stack(ctl->rpid, (uint64_t) ctl->orig.regs.sp, 8);

	ptrace(PTRACE_GETREGSET, ctl->rpid, 0x410, &gcs_iov);
	dump_gcs_slots(ctl->rpid, gcs.gcspr_el0, 0, 0);

	// __FILE__, __LINE__,
	if (!ctl->remote_map)
		return 0;

	// ctl->orig.regs.sp = (gcs.gcspr_el0 + 0x10) & ~0xF;
	// ctl->orig.regs.pc = ctl->orig.regs.regs[30];

	pr_debug("[compel_cure_remote]: ctl->orig.regs.sp = %llx\n",  (unsigned long long)ctl->orig.regs.sp);
	pr_debug("[compel_cure_remote]: ctl->orig.regs.pc = %llx\n",  (unsigned long long)ctl->orig.regs.pc);


	// if (ptrace(PTRACE_PEEKDATA, ctl->rpid, (void*)ctl->orig.regs.sp, &test_value) == -1) {
	// 	pr_perror("Stack at 0x%llx is not accessible: %s", (unsigned long long) ctl->orig.regs.sp, strerror(errno));
	// 	return -1;
	// } else {
	// 	pr_info("Stack at 0x%llx is accessible, value: 0x%llx", (unsigned long long) ctl->orig.regs.sp, (unsigned long long) test_value);
	// }

	err = compel_syscall(ctl, __NR(munmap, !compel_mode_native(ctl)), &ret, (unsigned long)ctl->remote_map,
			     ctl->map_length, 0, 0, 0, 0);
	if (err)
		return err;

	pr_info("compel_syscall ✅\n");

	if (ret) {
		pr_err("munmap for remote map %p, %lu returned %lu\n", ctl->remote_map, ctl->map_length, ret);
		return -1;
	}

	return 0;
}

int compel_cure_local(struct parasite_ctl *ctl)
{
	int ret = 0;
	pr_info("Curing local\n");

	if (ctl->local_map) {
		if (munmap(ctl->local_map, ctl->map_length)) {
			pr_err("munmap failed (pid: %d)\n", ctl->rpid);
			ret = -1;
		}
	}

	free(ctl);
	return ret;
}

int compel_cure(struct parasite_ctl *ctl)
{
	int ret;

	pr_info("compel_cure");

	ret = compel_cure_remote(ctl);
	if (!ret)
		ret = compel_cure_local(ctl);

	return ret;
}

void *compel_parasite_args_p(struct parasite_ctl *ctl)
{
	return ctl->args;
}

void *compel_parasite_args_s(struct parasite_ctl *ctl, unsigned long args_size)
{
	BUG_ON(args_size > ctl->args_size);
	return compel_parasite_args_p(ctl);
}

int compel_run_in_thread(struct parasite_thread_ctl *tctl, unsigned int cmd)
{
	int pid = tctl->tid;
	struct parasite_ctl *ctl = tctl->ctl;
	struct thread_ctx *octx = &tctl->th;
	void *stack = ctl->r_thread_stack;
	user_regs_struct_t regs = octx->regs;
	int ret;

	*ctl->cmd = cmd;

	ret = parasite_run(pid, PTRACE_CONT, ctl->parasite_ip, stack, &regs, octx);
	if (ret == 0)
		ret = parasite_trap(ctl, pid, &regs, octx, true);
	if (ret == 0)
		ret = (int)REG_RES(regs);

	if (ret)
		pr_err("Parasite exited with %d\n", ret);

	return ret;
}

/*
 * compel_unmap() is used for unmapping parasite and restorer blobs.
 * A blob can contain code for unmapping itself, so the process is
 * trapped on the exit from the munmap syscall.
 */
int compel_unmap(struct parasite_ctl *ctl, unsigned long addr)
{
	user_regs_struct_t regs = ctl->orig.regs;
	pid_t pid = ctl->rpid;
	int ret = -1;

	ret = parasite_run(pid, PTRACE_SYSCALL, addr, ctl->rstack, &regs, &ctl->orig);
	if (ret)
		goto err;

	ret = compel_stop_on_syscall(1, __NR(munmap, 0), __NR(munmap, 1));

	/*
	 * Don't touch extended registers here: they were restored
	 * with rt_sigreturn from sigframe.
	 */
	if (restore_thread_ctx(pid, &ctl->orig, false))
		ret = -1;
err:
	return ret;
}

int compel_stop_pie(pid_t pid, void *addr, bool no_bp)
{
	int ret;

	if (no_bp) {
		pr_debug("Force no-breakpoints restore of %d\n", pid);
		ret = 0;
	} else
		ret = ptrace_set_breakpoint(pid, addr);
	if (ret < 0)
		return ret;

	if (ret > 0) {
		/*
		 * PIE will stop on a breakpoint, next
		 * stop after that will be syscall enter.
		 */
		return 0;
	}

	/*
	 * No breakpoints available -- start tracing it
	 * in a per-syscall manner.
	 */
	ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	if (ret) {
		pr_perror("Unable to restart the %d process", pid);
		return -1;
	}
	return 0;
}

static bool task_is_trapped(int status, pid_t pid)
{
	if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~PTRACE_SYSCALL_TRAP) == SIGTRAP)
		return true;

	pr_err("Task %d is in unexpected state: %x\n", pid, status);
	if (WIFEXITED(status))
		pr_err("Task exited with %d\n", WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		pr_err("Task signaled with %d: %s\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
	if (WIFSTOPPED(status))
		pr_err("Task stopped with %d: %s\n", WSTOPSIG(status), strsignal(WSTOPSIG(status)));
	if (WIFCONTINUED(status))
		pr_err("Task continued\n");

	return false;
}

static inline int is_required_syscall(user_regs_struct_t *regs, pid_t pid, const int sys_nr, const int sys_nr_compat)
{
	struct user_gcs gcs;
	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };
	const char *mode = user_regs_native(regs) ? "native" : "compat";
	int req_sysnr = user_regs_native(regs) ? sys_nr : sys_nr_compat;

	pr_debug("%d (%s) is going to execute the syscall %lu, required is %d\n", pid, mode, REG_SYSCALL_NR(*regs),
		 req_sysnr);

	if (ptrace(PTRACE_GETREGSET, pid, 0x410, &gcs_iov) != 0) {
        pr_perror("GCS state not available for %d\n", pid);
        return -1;
    }

	dump_gcs_slots(pid, gcs.gcspr_el0, 0, 0xfffff7def000);

	return (REG_SYSCALL_NR(*regs) == req_sysnr);
}

/*
 * Trap tasks on the exit from the specified syscall
 *
 * tasks - number of processes, which should be trapped
 * sys_nr - the required syscall number
 * sys_nr_compat - the required compatible syscall number
 */
int compel_stop_on_syscall(int tasks, const int sys_nr, const int sys_nr_compat)
{
	enum trace_flags trace = tasks > 1 ? TRACE_ALL : TRACE_ENTER;
	user_regs_struct_t regs;
	int status, ret;
	pid_t pid;
	struct user_gcs gcs;
	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };

	/* Stop all threads on the enter point in sys_rt_sigreturn */
	while (tasks) {
		pid = wait4(-1, &status, __WALL, NULL);
		if (pid == -1) {
			pr_perror("wait4 failed");
			return -1;
		}

		pr_info("wait4: pid=%d status=0x%x\n", pid, status);
		if (!task_is_trapped(status, pid)) {
			pr_debug("\t 😦 oh noo IT'S A TRAP!\n");
			ptrace(PTRACE_GETREGSET, pid, 0x410 , &gcs_iov);
			dump_stack(pid, regs.sp, 8);
			dump_gcs_slots(pid, gcs.gcspr_el0, 0, 0xfffff7def000);
			pr_err("💥 Crash: PID=%d PC=0x%llx SP=0x%llx REGS[8]=0x%llx\n",
       			pid, regs.pc, regs.sp, regs.regs[8]);
			pr_err("task_is_trapped() failed for pid=%d status=0x%x\n", pid, status);
			dump_proc_maps(pid, false);
			dump_mem_via_dd(pid, regs.pc);
			return -1;
		}

		pr_debug("%d was trapped\n", pid);

		if ((WSTOPSIG(status) & PTRACE_SYSCALL_TRAP) == 0) {
			/*
			 * On some platforms such as ARM64, it is impossible to
			 * pass through a breakpoint, so let's clear it right
			 * after it has been triggered.
			*/
			if (ptrace_flush_breakpoints(pid)) {
				pr_err("Unable to clear breakpoints\n");
				return -1;
			}
			goto goon;
		}
		if (trace == TRACE_EXIT) {
			trace = TRACE_ENTER;
			pr_debug("`- Expecting exit\n");
			goto goon;
		}
		if (trace == TRACE_ENTER)
			trace = TRACE_EXIT;

		ret = ptrace_get_regs(pid, &regs);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}

		// pr_debug("[TRACE] pid=%d at syscall %llu (wanted: %d/%d)\n",
		// 		pid, (unsigned long long)regs.regs[8], sys_nr, sys_nr_compat);

		if (is_required_syscall(&regs, pid, sys_nr, sys_nr_compat)) {

			// Hacks Ahead
			if (sys_nr == 139) {
				// 	dump_gcs_slots(pid, gcs.gcspr_el0, 0, 0xfffff7def000);
				// 	// cap
				// pr_debug("is_required_syscall -> st_sigrekeke\n");
				// ptrace(PTRACE_GETREGSET, pid, 0x410 , &gcs_iov);
				// gcs.gcspr_el0 = 0x0000fffff7deffc8;
				// ptrace(PTRACE_SETREGSET, pid, 0x410, &gcs_iov);
				// ptrace(PTRACE_POKEDATA, pid, (void*)gcs.gcspr_el0, 0x0000fffff7def000);
			// 	// ptrace(PTRACE_POKEDATA, pid, (void*)gcs.gcspr_el0-8, 0xfffff7def000);
			// 	// gcs.gcspr_el0 -= 8;
			// 	ptrace(PTRACE_GETREGSET, pid, 0x410, &gcs_iov);
			// 	dump_gcs_slots(pid, gcs.gcspr_el0, 0, 0xfffff7def000);
			// 	dump_stack(pid, regs.sp, 8);
			}

			/*
			 * The process is going to execute the required syscall,
			 * the next stop will be on the exit from this syscall
			 */
			ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			if (ret) {
				pr_perror("ptrace");
				return -1;
			}

			pid = wait4(pid, &status, __WALL, NULL);
			if (pid == -1) {
				pr_perror("wait4 failed");
				return -1;
			}

			if (!task_is_trapped(status, pid))
				return -1;

			pr_debug("%d was stopped\n", pid);
			tasks--;
			continue;
		}
	goon:
		ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}
	}

	return 0;
}

int compel_mode_native(struct parasite_ctl *ctl)
{
	return user_regs_native(&ctl->orig.regs);
}

static inline k_rtsigset_t *thread_ctx_sigmask(struct thread_ctx *tctx)
{
	return &tctx->sigmask;
}

k_rtsigset_t *compel_thread_sigmask(struct parasite_thread_ctl *tctl)
{
	return thread_ctx_sigmask(&tctl->th);
}

k_rtsigset_t *compel_task_sigmask(struct parasite_ctl *ctl)
{
	return thread_ctx_sigmask(&ctl->orig);
}

int compel_get_thread_regs(struct parasite_thread_ctl *tctl, save_regs_t save, void *arg)
{
	return compel_get_task_regs(tctl->tid, &tctl->th.regs, &tctl->th.ext_regs, save, arg, tctl->ctl->ictx.flags);
}

struct infect_ctx *compel_infect_ctx(struct parasite_ctl *ctl)
{
	return &ctl->ictx;
}

struct parasite_blob_desc *compel_parasite_blob_desc(struct parasite_ctl *ctl)
{
	return &ctl->pblob;
}

uint64_t compel_get_leader_sp(struct parasite_ctl *ctl)
{
	return REG_SP(ctl->orig.regs);
}

uint64_t compel_get_thread_sp(struct parasite_thread_ctl *tctl)
{
	return REG_SP(tctl->th.regs);
}

uint64_t compel_get_leader_ip(struct parasite_ctl *ctl)
{
	return REG_IP(ctl->orig.regs);
}

uint64_t compel_get_thread_ip(struct parasite_thread_ctl *tctl)
{
	return REG_IP(tctl->th.regs);
}

void compel_set_leader_ip(struct parasite_ctl *ctl, uint64_t v)
{
	SET_REG_IP(ctl->orig.regs, v);
}

void compel_set_thread_ip(struct parasite_thread_ctl *tctl, uint64_t v)
{
	SET_REG_IP(tctl->th.regs, v);
}

void compel_get_stack(struct parasite_ctl *ctl, void **rstack, void **r_thread_stack)
{
	if (rstack)
		*rstack = ctl->rstack;
	if (r_thread_stack)
		*r_thread_stack = ctl->r_thread_stack;
}
