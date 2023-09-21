#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "anti_debugger.h"
#include "utils.h"

static char *getexe(int pid) {
    struct stat sb;
    ssize_t bufsize;
    ssize_t nbytes;
    char *buf;

    char proc[snprintf(NULL, 0, "/proc/%d/exe", pid) + 1];

    sprintf(proc, "/proc/%d/exe", pid);

    if (lstat(proc, &sb) == -1) {
        return NULL;
    }

    bufsize = sb.st_size + 1;
    if (sb.st_size == 0)
        bufsize = PATH_MAX;

    buf = malloc(bufsize);
    if (buf == NULL) {
        return NULL;
    }
    nbytes = readlink(proc, buf, bufsize);
    if (nbytes == -1) {
        free(buf);
        return NULL;
    }

    return buf;
}

int detect_debugger() {
    //if (ptrace(PTRACE_TRACEME, 0, 1, 0) != 0) {
    //    printf("don't trace me!!\n");
    //    return 1;
    //}

    //if(prctl(PR_SET_DUMPABLE, 0) < 0) {
    //    return 1;
    //}

    int i = 0;
    //char *exe = getexe(getpid());
    char *pexe = getexe(getppid());

    //char sh[] = {'a', 't', ' ', '\n', 't', 'e', '.', '*', 's', 'h', 0};
    //if (fnmatch(sh, pexe, 0)) {
    int len = strlen(pexe);
    //if (pexe[len-2] != 's' || pexe[len-1] != 'h') {
    if (!(pexe[len-2] == 's' && pexe[len-1] == 'h') && !(pexe[len-3] == 'c' && pexe[len-2] == 'a' && pexe[len-1] == 't')){
        i = 1;
    }

    //free(exe);
    free(pexe);
    return i;
}
