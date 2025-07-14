#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <execinfo.h>
#include <stdlib.h>
#include "debug.h"
// #include "uapi/compel/asm/infect-types.h"

// void read_gcs(struct user_gcs *gcs) {
// 	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };

//     ptrace(PTRACE_GETREGSET, pid, 0x410 /* NT_ARM_GCS */, &gcs_iov);

//     return gcs_iov
// }

// void write_gcs(struct user_gcs *gcs, bool dump) {
//     struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };

//     ptrace(PTRACE_SETREGSET, pid, 0x410, &gcs_iov);

//     if dump {
//         read_gcs(gcs)
//         dump_gcs_slots(pid, gcs.gcspr_el0, 0, 0xfffff7def000);
//     }
// }

void print_callstack(void) {
    void *buffer[64];
    int nptrs = backtrace(buffer, 64);
    char **symbols = backtrace_symbols(buffer, nptrs);

    printf("🔎 Call stack (%d frames):\n", nptrs);
    for (int i = 0; i < nptrs; i++) {
        printf("  [%d] %s\n", i, symbols[i]);
    }
    free(symbols);
}

static void _print_stack(FILE *out, const char *tag) {
    void *sp;
    char line[256];
    FILE *maps;
    uintptr_t stack_start = 0, stack_end = 0;
    uint64_t *sp_words;

    asm volatile ("mov %0, sp" : "=r"(sp));

    fprintf(out, "\n=== [%s] Stack pointer (SP) = %p ===\n", tag, sp);

    maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("fopen /proc/self/maps");
        return;
    }

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "[stack]")) {
            sscanf(line, "%lx-%lx", &stack_start, &stack_end);
            fprintf(out, "[stack] region: 0x%lx - 0x%lx\n", stack_start, stack_end);
            break;
        }
    }
    fclose(maps);

    fprintf(out, "🔎 Stack memory around SP:\n");

    sp_words = (uint64_t *)sp;

    for (int i = -4; i <= 4; i++) {
        uint64_t *addr = sp_words + i;
        uint64_t value = *addr;
        const char *marker = (i == 0) ? "<=== SP" : "";
        fprintf(out, "  [%2d] %p : 0x%016lx %s\n", i, addr, value, marker);
    }

    fprintf(out, "===============================\n");
    fflush(out);
}

void print_stack_info(const char *tag) {
    _print_stack(stdout, tag);
}

void print_stack_info_fp(FILE *log, const char *tag) {
    _print_stack(log, tag);
}