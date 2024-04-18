/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include "utility.h"
#include "common.h"
#include "entire_enc_t.h"
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
char g_enc_buff[ENC_BUF_SZ] = {'\0'};

void enc_print_log(int enc_debug_level, const char *fmt, ...)
{
    int printed_size;
    struct timeval tv;
    struct tm now;
    va_list ap;
  
    if (ENC_LOG_LEVEL >= enc_debug_level)
    { 
        ocall_get_current_time(&tv); 
        ocall_localtime(&tv.tv_sec, &now);
        va_start(ap, fmt);
        printed_size = snprintf(g_enc_buff, BUFSIZ, "[ENC.] [%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now.tm_mday, (now.tm_mon + 1), (now.tm_year + 1900), now.tm_hour, now.tm_min, now.tm_sec, tv.tv_usec);
        vsnprintf(&g_enc_buff[printed_size], (BUFSIZ-printed_size-1), fmt, ap);
        va_end(ap);
        ocall_print_string(g_enc_buff);
    }
}

void t_time(struct timeval *current_t)
{
    ocall_get_current_time((struct timeval*)current_t);
}

/* itoa is not available within the enclave */
char* itoa(int num, char* str, int base)
{
    int i = 0;
    bool isNegative = false;
    char local_str[20];
    int result_str_len;
 
    /* Handle 0 explicitly, otherwise empty string is printed for 0 */
    if (num == 0)
    {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }
 
    // In standard itoa(), negative numbers are handled only with
    // base 10. Otherwise numbers are considered unsigned.
    if (num < 0 && base == 10)
    {
        isNegative = true;
        num = -num;
    }
 
    // Process individual digits
    while (num != 0)
    {
        int rem = num % base;
        local_str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0';
        num = num/base;
    }
 
    // If number is negative, append '-'
    if (isNegative)
        local_str[i++] = '-';
 
    result_str_len = i;

    for (i = 0; i < result_str_len; i++)
    {
        str[i] = local_str[result_str_len - i - 1];
    }

    str[i] = '\0';
 
    return str;
}