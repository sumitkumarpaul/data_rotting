/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#define TLS_CLIENT "TLS client: "
#define TLS_SERVER "TLS server: "
#define PRINT_PREFIX "[Enclave 0]"

#define CLIENT_PAYLOAD "GET / HTTP/1.0\r\n\r\n"
#define SERVER_PAYLOAD                                   \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection : </p>\r\n"                \
    "A message from TLS server inside enclave\r\n"

#define CLIENT_PAYLOAD_SIZE strlen(CLIENT_PAYLOAD)
#define SERVER_PAYLOAD_SIZE strlen(SERVER_PAYLOAD)

#define ENC_BUF_SZ 204800 
extern char g_enc_buffer[];
extern char g_enc_buffer1[];
extern char g_ts_ip[];
extern int  g_ts_port;

#define ENC_DEBUG_LEVEL_NONE            (0)
#define ENC_DEBUG_LEVEL_ONLY_SPECIAL    (1)
#define ENC_DEBUG_LEVEL_ERROR           (2)
#define ENC_DEBUG_LEVEL_INFO            (3)
#define ENC_DEBUG_LEVEL_DUMP            (4)


// put common files here in a definition of Macro to reduce
// redundancy code
#ifdef CLIENT_USE_QVL
#include "sgx_utls.h"
#define PRINT printf
#define GETCURRTIME ocall_get_current_time
#define VERIFY_CALLBACK  tee_verify_certificate_with_evidence_host
#define FREE_SUPDATA tee_free_supplemental_data_host
#else
#include "sgx_ttls.h"
#define PRINT T_PRINT
#define GETCURRTIME T_TIME
#define VERIFY_CALLBACK tee_verify_certificate_with_evidence
#define FREE_SUPDATA tee_free_supplemental_data
#endif

#ifdef TDX_ENV
#define T_PRINT printf
#define T_TIME time
#else
extern void enc_print_log(int enc_debug_level, const char* fmt, ...);
extern void t_time(struct timeval *c_time);
extern char* itoa(int num, char* str, int base);
#define T_PRINT enc_print_log
#define T_TIME t_time
#define stdout ((void*)1)
#define stderr ((void*)2)
#endif
