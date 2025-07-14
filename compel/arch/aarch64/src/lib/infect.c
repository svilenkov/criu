#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <linux/types.h>

#include <compel/plugins/std/syscall-codes.h>
#include "common/page.h"
#include "uapi/compel/asm/infect-types.h"
#include "log.h"
#include "errno.h"
#include "infect.h"
#include "infect-priv.h"
#include "asm/breakpoints.h"
#include <linux/sched.h>

#define PR_SHADOW_STACK_ENABLE      (1UL << 0)
#define PR_SHADOW_STACK_WRITE		(1UL << 1)
#define PR_SHADOW_STACK_PUSH		(1UL << 2)

unsigned __page_size = 0;
unsigned __page_shift = 0;

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x01, 0x00, 0x00, 0xd4, /* SVC #0 */
	0x00, 0x00, 0x20, 0xd4	/* BRK #0 */
};

static const int code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline void __always_unused __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	struct fpsimd_context *fpsimd = RT_SIGFRAME_FPU(sigframe);
	struct gcs_context *gcs = RT_SIGFRAME_GCS(sigframe);

	memcpy(sigframe->uc.uc_mcontext.regs, regs->regs, sizeof(regs->regs));

	pr_debug("sigreturn_prep_regs_plain: sp %lx pc %lx\n", (long)regs->sp, (long)regs->pc);

	sigframe->uc.uc_mcontext.sp = regs->sp;
	sigframe->uc.uc_mcontext.pc = regs->pc;
	sigframe->uc.uc_mcontext.pstate = regs->pstate;

	memcpy(fpsimd->vregs, fpregs->fpstate.vregs, 32 * sizeof(__uint128_t));

	fpsimd->fpsr = fpregs->fpstate.fpsr;
	fpsimd->fpcr = fpregs->fpstate.fpcr;

	fpsimd->head.magic = FPSIMD_MAGIC;
	fpsimd->head.size = sizeof(*fpsimd);

	gcs->head.magic = GCS_MAGIC;
	gcs->head.size = sizeof(*gcs);
	gcs->reserved = 0;
	gcs->gcspr = fpregs->gcs.gcspr_el0 - 8;
	gcs->features_enabled = fpregs->gcs.features_enabled;

	pr_debug("sigframe gcspr %llx enabled %llx\n", fpregs->gcs.gcspr_el0 - 8, fpregs->gcs.features_enabled);

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *fpsimd, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	struct iovec iov;
	int ret;

	struct user_gcs gcs;
	struct iovec gcs_iov = {
		.iov_base = &fpsimd->gcs,
		.iov_len = sizeof(fpsimd->gcs),
	};

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))) {
		pr_perror("Failed to obtain CPU registers for %d", pid);
		goto err;
	}

	iov.iov_base = &fpsimd->fpstate;
	iov.iov_len = sizeof(fpsimd->fpstate);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov))) {
		pr_perror("Failed to obtain FPU registers for %d", pid);
		goto err;
	}

	pr_debug("compel_get_task_regs: %s:%d", __FILE__, __LINE__);
	pr_info("\t=== [GCS] TEST GCS PRINT ===\n");
	if (ptrace(PTRACE_GETREGSET, pid, 0x410, &gcs_iov) == 0) {
		gcs = fpsimd->gcs;
		pr_info("GCSPR_EL0 for %d: 0x%llx, features: 0x%llx\n", pid, gcs.gcspr_el0, gcs.features_enabled);

		if (gcs.features_enabled & PR_SHADOW_STACK_ENABLE) {
			pr_info("[GCS] GCSPR_EL0 (stack pointer):        0x%llx <-- THIS IS JUST A VIRTUAL ADDRESS\n", gcs.gcspr_el0);
			pr_info("[GCS] features_enabled:                 0x%llx <-- THIS IS THE BITFIELD (flags!)\n", gcs.features_enabled);
			pr_info("[GCS] PR_SHADOW_STACK_ENABLE (bit 0):   0x%llx (shadow stack is ENABLED if this is set in features_enabled)\n", (unsigned long long)PR_SHADOW_STACK_ENABLE);
		} else {
			pr_info("❌ GCS is NOT enabled\n");
		}

	} else {
		pr_warn("GCS state not available for %d (likely unsupported)\n", pid);
	}

	ret = save(pid, arg, regs, fpsimd);
err:
	return ret;
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	struct iovec iov;

	pr_info("Restoring GP/FPU registers for %d\n", pid);

	iov.iov_base = ext_regs;
	iov.iov_len = sizeof(*ext_regs);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRFPREG, &iov)) {
		pr_perror("Failed to set FPU registers for %d", pid);
		return -1;
	}
	return 0;
}

int compel_set_task_gcs_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	struct iovec iov;

	pr_info("Restoring GCS registers for %d\n", pid);
	pr_info("Restoring GCS: gcspr=%llx features=%llx\n", ext_regs->gcs.gcspr_el0, ext_regs->gcs.features_enabled);

	iov.iov_base = &ext_regs->gcs;
	iov.iov_len  = sizeof(ext_regs->gcs);

	if (ptrace(PTRACE_SETREGSET, pid, 0x410, &iov)) {
		pr_perror("Failed to set GCS registers for %d", pid);
		return -1;
	}

	return 0;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	regs.regs[8] = (unsigned long)nr;
	regs.regs[0] = arg1;
	regs.regs[1] = arg2;
	regs.regs[2] = arg3;
	regs.regs[3] = arg4;
	regs.regs[4] = arg5;
	regs.regs[5] = arg6;
	regs.regs[6] = 0;
	regs.regs[7] = 0;

	pr_debug("🕵️ syscall nr=%d args=[%lx,%lx,%lx,%lx,%lx,%lx]\n", nr, arg1, arg2, arg3, arg4, arg5, arg6);
	err = compel_execute_syscall(ctl, &regs, code_syscall);
	// regs.regs[0] on AArch64 is a 64-bit unsigned value,
	*ret = regs.regs[0];

	pr_debug("🕵️ syscall ret=%lld, err=%d\n", (__u64) *ret, err);

	return err;
}

void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long map;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map, (unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0 || (long)map < 0)
		map = 0;

	return (void *)map;
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	pr_debug("%s:%d#%s\n", __FILE__, __LINE__, __func__);
	regs->pc = new_ip;

	// if (stack)
	// regs->sp = (unsigned long)stack;
	pr_debug("...setting NEW stack %llx\n with IP=%llx\n", regs->sp, regs->pc);
	regs->sp = (unsigned long)stack;
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm64/include/asm/memory.h
 *   arch/arm64/Kconfig
 *
 * TODO: handle 32 bit tasks
 */
#define TASK_SIZE_MIN (1UL << 39)
#define TASK_SIZE_MAX (1UL << 48)

unsigned long compel_task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}

static struct hwbp_cap *ptrace_get_hwbp_cap(pid_t pid)
{
	static struct hwbp_cap info;
	static int available = -1;

	if (available == -1) {
		unsigned int val;
		struct iovec iovec = {
			.iov_base = &val,
			.iov_len = sizeof(val),
		};

		if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_BREAK, &iovec) < 0)
			available = 0;
		else {
			info.arch = (char)((val >> 8) & 0xff);
			info.bp_count = (char)(val & 0xff);

			available = (info.arch != 0);
		}
	}

	return available == 1 ? &info : NULL;
}

int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	k_rtsigset_t block;
	struct hwbp_cap *info = ptrace_get_hwbp_cap(pid);
	struct user_hwdebug_state regs = {};
	unsigned int ctrl = 0;
	struct iovec iovec;

	if (info == NULL || info->bp_count == 0)
		return 0;

	/*
	 * The struct is copied from `arch/arm64/include/asm/hw_breakpoint.h` in
	 * linux kernel:
	 *  struct arch_hw_breakpoint_ctrl {
	 *  	__u32 __reserved        : 19,
	 *  	len             : 8,
	 *  	type            : 2,
	 *  	privilege       : 2,
	 *  	enabled         : 1;
	 *  };
	 *
	 * The part of `struct arch_hw_breakpoint_ctrl` bits meaning is defined
	 * in <<ARM Architecture Reference Manual for A-profile architecture>>,
	 * D13.3.2 DBGBCR<n>_EL1, Debug Breakpoint Control Registers.
	 */
	ctrl = ARM_BREAKPOINT_LEN_4;
	ctrl = (ctrl << 2) | ARM_BREAKPOINT_EXECUTE;
	ctrl = (ctrl << 2) | AARCH64_BREAKPOINT_EL0;
	ctrl = (ctrl << 1) | ENABLE_HBP;
	regs.dbg_regs[0].addr = (__u64)addr;
	regs.dbg_regs[0].ctrl = ctrl;
	iovec.iov_base = &regs;
	iovec.iov_len = (offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(regs.dbg_regs[0]));

	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &iovec))
		return -1;

	/*
	 * FIXME(issues/1429): SIGTRAP can't be blocked, otherwise its handler
	 * will be reset to the default one.
	 */
	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &block)) {
		pr_perror("Can't block signals for %d", pid);
		return -1;
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
		pr_perror("Unable to restart the  stopped tracee process %d", pid);
		return -1;
	}

	return 1;
}

int ptrace_flush_breakpoints(pid_t pid)
{
	struct hwbp_cap *info = ptrace_get_hwbp_cap(pid);
	struct user_hwdebug_state regs = {};
	unsigned int ctrl = 0;
	struct iovec iovec;

	if (info == NULL || info->bp_count == 0)
		return 0;

	ctrl = ARM_BREAKPOINT_LEN_4;
	ctrl = (ctrl << 2) | ARM_BREAKPOINT_EXECUTE;
	ctrl = (ctrl << 2) | AARCH64_BREAKPOINT_EL0;
	ctrl = (ctrl << 1) | DISABLE_HBP;
	regs.dbg_regs[0].addr = 0ul;
	regs.dbg_regs[0].ctrl = ctrl;

	iovec.iov_base = &regs;
	iovec.iov_len = (offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(regs.dbg_regs[0]));

	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &iovec))
		return -1;

	return 0;
}

bool __compel_gcs_enabled(struct user_gcs *gcs)
{
	if (gcs->features_enabled & PR_SHADOW_STACK_ENABLE)
		return true;

	return false;
}

#define GCS_CAP_ADDR_MASK 0xFFFFFFFFFFFFF000ULL
// #define GCS_CAP(x) ((((unsigned long)x) & GCS_CAP_ADDR_MASK) | GCS_CAP_VALID_TOKEN)
#define GCS_SIGNAL_CAP(addr) (((unsigned long)addr) & GCS_CAP_ADDR_MASK)
#define GCS_CAP_VALID_TOKEN 0x1

#define SHADOW_STACK_SET_MARKER (1ULL << 1)
#define SHADOW_STACK_SET_TOKEN (1ULL << 0)

int inject_gcs_cap_token(struct parasite_ctl *ctl, pid_t pid, struct user_gcs *gcs)
{
	struct iovec gcs_iov = { .iov_base = gcs, .iov_len = sizeof(*gcs) };

	// uint64_t sentinel = 0xDEADBEEFDEADBEEF;
	uint64_t want = 0xfffff7def000;
    int delta = 0;
	uint64_t token_addr = gcs->gcspr_el0 - 8 + delta;
	uint64_t sigtramp_addr = gcs->gcspr_el0 - 16 + delta;

	uint64_t cap_token = ALIGN_DOWN(GCS_SIGNAL_CAP(token_addr), 8);
	// uint64_t cap_token = GCS_CAP(token_addr);
	unsigned long restorer_addr;
	// cap_token = 0xDEADBEEFDEADBEEF;;

	if (cap_token != want) {
		pr_perror("gcs: Cap toke expectation mismatch: got 0x%llx, expected 0x%llx\n", (unsigned long long) cap_token, (unsigned long long) want);
		return -1;
	}

	pr_debug("🔎 GCS injection preparation:\n");
	pr_debug("\t>> GCSPR_EL0 (register): 0x%llx\n", gcs->gcspr_el0);
	pr_debug("\t>> GCSPR_EL0 (%d): 0x%llx\n", delta, (unsigned long long) token_addr);
	pr_debug("\t>> GCSPR_EL0 (%d): 0x%llx\n", delta - 8, (unsigned long long) sigtramp_addr);
	pr_debug("\t>> CAP_MASK: 0x%llx\n", (unsigned long long) GCS_CAP_ADDR_MASK);
	pr_debug("\t>> Expected cap token: 0x%llx\n", (unsigned long long) cap_token);
	pr_debug("\t>> 🥇 Actual GCS cap token 0x%lx at addr %p\n", cap_token, (void*)(token_addr));

	// Cap
	if (ptrace(PTRACE_POKEDATA, pid, (void*)token_addr, cap_token)) {
		pr_perror("gcs: Inject GCS cap token failed");
		return -1;
	}

	// Tramp
	restorer_addr = ctl->parasite_ip;
	pr_debug("\t>> SIGTRAM (addr): 0x%llx\n", (unsigned long long) restorer_addr);
	if (ptrace(PTRACE_POKEDATA, pid, (void*)sigtramp_addr, restorer_addr)) {
		pr_perror("Inject GCS restorer failed");
		return -1;
	}

	// Update GCSPR_EL0
	// gcs->gcspr_el0 = token_addr - 8;
	gcs->gcspr_el0 = token_addr;
	if(ptrace(PTRACE_SETREGSET, pid, 0x410, &gcs_iov)) {
		pr_perror("gcs: PTRACE_SETREGS FAILED");
		return -1;
	}

	pr_info("At GCS setup: ctl->parasite_ip  = 0x%lx\n", ctl->parasite_ip);
	pr_info("At GCS setup: ctl->orig.regs.sp = 0x%llx\n", (unsigned long long)ctl->orig.regs.sp);
	pr_info("At GCS setup: gcspr_el0         = 0x%llx\n", (unsigned long long)gcs->gcspr_el0);

	if (ptrace(PTRACE_GETREGSET, pid, 0x410, &gcs_iov)) {
		pr_perror("gcs: PTRACE_GETREGSET failed");
		return -1;
	}

	pr_debug("gcs: After PTRACE_SETREGSET: gcspr_el0 = 0x%llx\n", gcs->gcspr_el0);
	return 0;
}

// static size_t page_size = 65536;

void __dump_gcs_slots(id_t pid, uint64_t gcspr_el0, int offset, uint64_t expected_token) {
	uint64_t start;
	struct iovec local;
	struct iovec remote;
	ssize_t n;

	enum { SLOTS = 8 };
    uint64_t buf[SLOTS];

	// uint64_t expected_token = 0xDEADBEEFDEADBEEF;
	if (offset == 0)
    	offset = 2;

	start = gcspr_el0 - (offset * 8); // start here

	local.iov_base  = buf;
	local.iov_len   = sizeof(buf);

	remote.iov_base = (void *)start;
	remote.iov_len  = sizeof(buf);

    n = process_vm_readv(pid, &local, 1, &remote, 1, 0);

	if (expected_token == 0)
        expected_token = 0xfffff7def000;

    if (n != sizeof(buf)) {
        pr_perror("process_vm_readv GCS dump");
        return;
    }

    pr_debug("🔎 GCS [gcspr_el0-%d .. gcspr_el0+16]:\n", offset * 8);
    for (int i = 0; i < SLOTS; ++i) {
        uint64_t addr = start + i * 8;
        const char *marker = "";

		if (buf[i] == expected_token && addr == gcspr_el0)
        	marker = "✅ CAP TOKEN & ◀─── [GCSPR_EL0]";
	    else if (buf[i] == expected_token)
			marker = "✅ CAP TOKEN";
		else if (addr == gcspr_el0)
			marker = "◀─── [GCSPR_EL0]";
		else if (buf[i] == 0)
			marker = "(zero)";



        pr_debug("  [%2d] 0x%016llx : 0x%016llx %s\n",
            i, (unsigned long long)addr,
            (unsigned long long)buf[i],
            marker);
    }
}

int parasite_setup_gcs(struct parasite_ctl *ctl)
{
	struct user_gcs gcs;
	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };
	pid_t pid = ctl->rpid;
	unsigned long long val1, val2;

	if (ptrace(PTRACE_GETREGSET, pid, 0x410, &gcs_iov) != 0) {
        pr_perror("GCS state not available for %d\n", pid);
        return -1;
    }

   if (__compel_gcs_enabled(&gcs)) {
		val1 = ptrace(PTRACE_PEEKDATA, pid, (void*)(gcs.gcspr_el0 - 16), NULL);
		val2 = ptrace(PTRACE_PEEKDATA, pid, (void*)(gcs.gcspr_el0 - 8), NULL);

		pr_debug("BEFORE injection:\n");
		pr_debug("  [gcspr_el0-16] = 0x%llx\n", val1);
		pr_debug("  [gcspr_el0-8 ] = 0x%llx\n", val2);

        // if (inject_gcs_for_pid(page_size()) == NULL) {
        if (inject_gcs_cap_token(ctl, pid, &gcs)) {
            pr_perror("Failed to inject GCS cap token for %d\n", pid);
            return -1;
        }
		pr_debug("[GCS DUMP]: After Injection:\n");
		__dump_gcs_slots(pid, gcs.gcspr_el0, 4, 0);
    } else {
        pr_perror("GCS not enabled for %d\n", pid);
        return -1;
    }

	return 0;
}
