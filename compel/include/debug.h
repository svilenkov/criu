#pragma once
#include <stdio.h>

void print_stack_info(const char *tag);
void print_stack_info_fp(FILE *log, const char *tag);
void print_callstack(void);
bool get_ss_vma_range(pid_t pid, unsigned long *start, unsigned long *end);
void dump_proc_maps(pid_t pid, bool smaps);