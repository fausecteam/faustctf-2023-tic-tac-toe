#ifndef ANTI_DBG_H
#define ANTI_DBG_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fnmatch.h>

int detect_debugger();

#endif
