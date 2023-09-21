#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#define ARRAYSIZE(a) (int)(sizeof(a) / sizeof(a[0]))

//void report_err(const char *err);
void remove_new_line(char *);
void read_input(char *, int);
//int parse_positive_int_or_die(char *);
int __real_puts(const char *);
int __wrap_puts(const char *);

#endif
