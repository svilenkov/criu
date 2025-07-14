#pragma once
#include <stdio.h>

void print_stack_info(const char *tag);
void print_stack_info_fp(FILE *log, const char *tag);
void print_callstack(void);