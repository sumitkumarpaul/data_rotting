#ifndef LIBENC_DEBUG_H
#define LIBENC_DEBUG_H



#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#define DEBUG_LEVEL_NONE        (0)
#define DEBUG_LEVEL_ERROR       (1)
#define DEBUG_LEVEL_INFO        (2)

#define PRINT_FILE              stderr
#define LOG_LEVEL               DEBUG_LEVEL_ERROR


int print_log(int debug_level, const char* format, ...);

#endif
