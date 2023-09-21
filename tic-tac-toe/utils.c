#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#define ARRAYSIZE(a) (int)(sizeof(a) / sizeof(a[0]))

//void report_err(const char *);
void remove_new_line(char *);
void read_input(char *, int);

//void report_err(const char *msg) { errx(EXIT_FAILURE, "%s", msg); }

int __real_puts(const char *s);

int __wrap_puts(const char *s) {
    char new[strlen(s) + 1];
    for (int i = 0; i < strlen(s) + 1; i++) {
        new[i] = '\0';
    }
    for (int i = 0; i < strlen(s); i++) {
        new[i] = s[i] ^ 0b101011;
    }
    return __real_puts((char *)new);
}

void remove_new_line(char *str) {
    char *nl = strchr(str, '\n');
    if (nl != NULL)
        *nl = '\0';
}

void read_input(char *val, int size) {
    //printf("%s", prompt);
    if (fgets(val, size, stdin) == NULL) {
        //if (ferror(stdin)) {
        //    report_err(err_msg);
        //    exit(EXIT_FAILURE);
        //}
        // exit(EXIT_SUCCESS);
        *val = '\0';
        return;
    }
    if (strlen(val) == size - 1 && val[size - 2] != '\n') {
        int c;
        do {
            c = getchar();
        } while (c != EOF && c != '\n');
        val[0] = '\0';
        return;
    }
    remove_new_line(val);
}

//int parse_positive_int_or_die(char *str) {
//    errno = 0;
//    char *endptr;
//    long x = strtol(str, &endptr, 10);
//    if (errno != 0) {
//        return -1;
//    }
//
//    if (str == endptr || *endptr != '\0') {
//        return -1;
//    }
//    if (x < 0) {
//        return -1;
//    }
//
//    if (x > INT_MAX) {
//        return -1;
//    }
//
//    return (int)x;
//}
