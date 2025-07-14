#include <unistd.h>
#include <string.h>
#include "log.h"
#include "restore.h"
#include "images/core.pb-c.h"

#ifndef setup_sas
static inline void setup_sas(struct rt_sigframe *sigframe, ThreadSasEntry *sas)
{
	if (sas) {
#define UC RT_SIGFRAME_UC(sigframe)

		UC->uc_stack.ss_sp = (void *)decode_pointer((sas)->ss_sp);
		UC->uc_stack.ss_flags = (int)(sas)->ss_flags;
		UC->uc_stack.ss_size = (size_t)(sas)->ss_size;
#undef UC
	}
}
#endif

void print_sigframe_table2(const struct rt_sigframe *f) {
    const struct cr_sigcontext *sc = RT_SIGFRAME_SIGCONTEXT(f);
	const struct gcs_context *gcs = RT_SIGFRAME_GCS(f);

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

	pr_debug("+-------------------[ GCS Context ]-------------------+\n");
	pr_debug("| %-12s | 0x%016llx |\n", "gcspr", gcs->gcspr);
	pr_debug("| %-12s | 0x%016llx |\n", "features", gcs->features_enabled);
	pr_debug("| %-12s | 0x%08x       |\n", "magic", gcs->head.magic);
	pr_debug("| %-12s | %u bytes   |\n", "size", gcs->head.size);
	pr_debug("+-----------------------------------------------------+\n");
}

int construct_sigframe(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe, k_rtsigset_t *blkset,
		       CoreEntry *core, pid_t pid)
{
	/*
	 * Copy basic register set in the first place: this will set
	 * rt_sigframe type: native/compat.
	 */
	if (restore_gpregs(sigframe, CORE_THREAD_ARCH_INFO(core)->gpregs))
		return -1;

	if (blkset)
		rt_sigframe_copy_sigset(sigframe, blkset);
	else
		rt_sigframe_erase_sigset(sigframe);

	if (restore_fpu(sigframe, core, pid))
		return -1;

	print_sigframe_table2(sigframe);

	// pr_debug("sigframe->gcs->gcspr = 0x%llx", sigframe->fp);

	if (RT_SIGFRAME_HAS_FPU(sigframe))
		if (sigreturn_prep_fpu_frame(sigframe, rsigframe))
			return -1;

	setup_sas(sigframe, core->thread_core->sas);

	// print_sigframe_table(sigframe);

	return 0;
}
