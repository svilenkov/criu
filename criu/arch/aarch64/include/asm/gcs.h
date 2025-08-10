#ifndef __CR_ASM_GCS_H__
#define __CR_ASM_GCS_H__

#include "gcs-types.h"

struct rst_gcs_info {
	unsigned long vma_start;       /* start of GCS VMA */
	unsigned long vma_size;        /* size of GCS VMA */
	unsigned long premapped_addr;  /* premapped buffer */
	unsigned long tmp_gcs;         /* temp area for GCS if needed */
	u64 gcspr_el0;                 /* GCS pointer */
	u64 features_enabled;          /* GCS flags */
};

#define rst_gcs_info rst_gcs_info

struct task_restore_args;
struct pstree_item;

int arch_gcs_prepare(struct pstree_item *item, CoreEntry *core,
		       struct task_restore_args *ta);
#define arch_gcs_prepare arch_gcs_prepare


int arch_shstk_trampoline(struct pstree_item *item, CoreEntry *core,
		      int (*func)(void *arg), void *arg);
#define arch_shstk_trampoline arch_shstk_trampoline

#ifdef CR_NOGLIBC
#include <compel/plugins/std/syscall.h>
#include <compel/cpu.h>
#include "vma.h"

static inline int gcs_map(unsigned long addr, unsigned long size)
{
	long gcspr = sys_map_shadow_stack(addr, size, 0x1);

	if (gcspr < 0) {
		pr_err("gcs: failed to map GCS at %lx: %ld\n", addr, gcspr);
		return -1;
	}

	if (gcspr != addr) {
		pr_err("gcs: address mismatch: need %lx, got %lx\n", addr, gcspr);
		return -1;
	}

	pr_info("gcs: mmapped GCS at %lx\n", gcspr);

	return 0;
}

/* clang-format off */
static always_inline void gcsss1(unsigned long *Xt)
{
	asm volatile (
		"sys #3, C7, C7, #2, %0\n"
		:
		: "rZ" (Xt)
		: "memory");
}

static always_inline unsigned long *gcsss2(void)
{
	unsigned long *Xt;

	asm volatile (
		"SYSL %0, #3, C7, C7, #3\n"
		: "=r" (Xt)
		:
		: "memory");

	return Xt;
}

static inline unsigned long *gcsstr(unsigned long val)
{
    unsigned long *ssp;

    asm volatile (
        "mov x0, %1\n"
        ".inst 0xd91f1c00\n"     // GCSSTR x0, [GCSPR_EL0 - 8]
        "mov %0, x0\n"
        : "=r"(ssp)
        : "r"(val)
        : "x0", "memory"
    );

    return ssp;  // This is the new SSP (after storing val)
}

static inline void gcsstrp(unsigned long addr, unsigned long val)
{
    asm volatile(
		"mov x0, %0\n"
        "mov x1, %1\n"
        ".inst 0xd91f1c01\n"  // GCSSTR x1, [x0]
		"mov x0, #0\n"
        :
        : "r"(addr), "r"(val)
        : "x0", "x1", "memory");
}
/* clang-format on */

static always_inline int gcs_restore(struct rst_gcs_info *gcs)
{
	unsigned long gcspr = gcs->vma_start + gcs->vma_size - 8;
	unsigned long gcs_top = gcs->vma_size / 8 - 1;
	unsigned long *gcs_data = (unsigned long *) gcs->premapped_addr;
	unsigned long val;
	unsigned long jump_to;

	if (!(gcs && gcs->features_enabled & PR_SHADOW_STACK_ENABLE)) {
		return 0;
	}

	if (!gcs->vma_start || !gcs->vma_size) {
		pr_warn("gcs: Cannot restore without vma start/size");
		return 0;
	}

	if(gcs_map(gcs->vma_start, gcs->vma_size)) {
		pr_err("gcs: unable to map shadow stack\n");
		return -1;
	}

	for (; gcspr >= gcs->gcspr_el0; gcspr -= 8, gcs_top--) {
		gcsstrp(gcspr, gcs_data[gcs_top]);
	}

	val = ALIGN_DOWN(GCS_SIGNAL_CAP(gcspr), 8);
	pr_debug("gcs: about to GCSSTR VAL=%lx write at GCSPR=%lx\n", val, gcspr);
	gcsstrp(gcspr, val);

	val = ALIGN_DOWN(GCS_SIGNAL_CAP(gcspr), 8) | 0x1;
	pr_debug("gcs: about to GCSSTR VAL=%lx write at GCSPR=%lx\n", val, gcspr);
	gcsstrp(gcspr - 8, val);

	jump_to = gcspr - 8;
	pr_debug("gcs: about to jump using GCSSS1 to: %lx\n", jump_to);
	gcsss1((unsigned long *) jump_to);

	return 0;
}
#define arch_gcs_restore gcs_restore

static always_inline int gcs_switch_to_restorer(struct rst_gcs_info *gcs)
{
	int ret;
	unsigned long *ssp;
	unsigned long addr;

	if (!(gcs && gcs->features_enabled & PR_SHADOW_STACK_ENABLE)) {
		return 0;
	}

	addr = gcs->premapped_addr + gcs->vma_size;

	if (addr % PAGE_SIZE != 0)
		pr_err("gcs: addr 0x%lx is NOT page-aligned (PAGE_SIZE=0x%lx)\n", addr, PAGE_SIZE);
	else
		pr_debug("gcs: addr 0x%lx is page-aligned\n", addr);

	ret = sys_munmap((void *) gcs->premapped_addr + gcs->vma_size, PAGE_SIZE);
	if (ret < 0) {
		pr_err("gcs: Failed to unmap aarea for dumpee GCS VMAs");
		return -1;
	}

	ret = gcs_map(addr, PAGE_SIZE);

	if (ret < 0) {
		pr_err("gcs: failed to gcs_map(0x%lx, PAGE_SIZE=0x%lx)\n", addr, PAGE_SIZE);
		return -1;
	}

	ssp = (unsigned long *)(addr + PAGE_SIZE - 8);
	gcsss1(ssp);

	return 0;
}
#define arch_gcs_switch_to_restorer gcs_switch_to_restorer

#endif /* CR_NOGLIBC */

#endif /* __CR_ASM_GCS_H__ */
