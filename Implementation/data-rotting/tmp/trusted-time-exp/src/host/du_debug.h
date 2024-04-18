#ifndef DU_DEBUG_H
#define DU_DEBUG_H



#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#define DEBUG_LEVEL_NONE        (0)
#define DEBUG_LEVEL_ERROR       (1)
#define DEBUG_LEVEL_INFO        (2)
#define DEBUG_LEVEL_DUMP        (3)

#define PRINT_FILE              stderr

int print_log(int debug_level, const char* format, ...);

#endif
