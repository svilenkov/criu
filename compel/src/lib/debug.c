#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <execinfo.h>
#include <stdlib.h>
#include "debug.h"

#include "log.h"
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

    pr_debug("🔎 Call stack (%d frames):\n", nptrs);
    for (int i = 0; i < nptrs; i++) {
        pr_debug("  [%d] %s\n", i, symbols[i]);
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

bool get_ss_vma_range(pid_t pid, unsigned long *start, unsigned long *end)
{
	char path[64];
	FILE *fp;
	char line[512];
	char block[8192] = "";
	size_t block_len = 0;

	snprintf(path, sizeof(path), "/proc/%d/smaps", pid);
	fp = fopen(path, "r");
	if (!fp) {
		pr_err("Failed to open %s\n", path);
		return false;
	}

	while (fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;

		if (strchr(line, '-') && strchr(line, ':')) {
			block[0] = 0;
			block_len = 0;
		}

		if (block_len + strlen(line) + 2 < sizeof(block)) {
			block_len += snprintf(block + block_len, sizeof(block) - block_len, "%s\n", line);
		}

		if (strncmp(line, "VmFlags:", 8) == 0 && strstr(line, " ss")) {
			// First line in block is always the VMA range line
			char *vma_line = strtok(block, "\n");
			if (vma_line) {
				if (sscanf(vma_line, "%lx-%lx", start, end) == 2) {
					pr_debug("SS VMA range: %lx-%lx\n", *start, *end);
					fclose(fp);
					return true;
				}
			}
		}
	}

	fclose(fp);
	return false;
}

static void filter_and_print_ss_block(const char *block)
{
	const char *keys[] = {
		"Size:", "KernelPageSize:", "MMUPageSize:",
		"Rss:", "Pss:", "Private_Dirty:", "Referenced:",
		"Anonymous:", "VmFlags:"
	};
	bool first_line;
	const size_t num_keys = sizeof(keys) / sizeof(keys[0]);

	char *line, *copy, *saveptr;

	copy = strdup(block);
	if (!copy)
		return;

	line = strtok_r(copy, "\n", &saveptr);

	first_line = true;
	while (line) {
		if (first_line) {
			pr_debug("  %s\n", line);  // Always print the first line (VMA range)
			first_line = false;
			continue;
		}

		for (size_t i = 0; i < num_keys; i++) {
			if (strncmp(line, keys[i], strlen(keys[i])) == 0) {
				pr_debug("  %s\n", line);
				break;
			}
		}
		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(copy);
}

void dump_proc_maps(pid_t pid, bool smaps) {
	char path[64];
	FILE *fp;
	char line[512];
	char block[8192] = "";
	size_t block_len = 0;

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

		if(smaps) {
			if (strchr(line, '-')  && strchr(line, ':')) {
				// new VMA text block
				// so reset buffa
				block[0] = 0;
				block_len = 0;

				// Always append range
			    // block_len += snprintf(block + block_len, sizeof(block) - block_len, "%s\n", line);
    			// continue;
			}

			if (block_len + strlen(line) + 2 < sizeof(block)) {
				block_len += snprintf(block + block_len, sizeof(block) - block_len, "%s\n", line);
			}

			if(strncmp(line, "VmFlags:", 8) == 0) {
				if (strstr(line, " ss"))
                    filter_and_print_ss_block(block);
					// pr_debug("SS: %s\n", block);
			}

			continue;
		}

		pr_debug("%s\n", line);
	}

	fclose(fp);
	pr_debug("=========================\n");
}
