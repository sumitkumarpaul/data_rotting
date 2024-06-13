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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "../common/common.h"
#include "../common/data_access.h"
#include "../common/data_provision.h"

extern "C"
{
    int ecall_enc_access_all_data(char *result, int *p_result_len, int max_result_sz, in_addr_t bc_ip);
};

char eligibility_str[200] = {0};

int enc_access_all_data(in_addr_t bc_ip);

int enc_check_SSN()
{
    int ret = -1;


    ret = 0;
exit:

    return ret;
}

int enc_check_age()
{
    int ret = -1;


    ret = 0;
exit:

    return ret;
}

int enc_check_income()
{
    int ret = -1;


    ret = 0;
exit:

    return ret;
}

int enc_access_all_data(in_addr_t bc_ip)
{
    int ret = -1;
    X509* priv_data_x509 = NULL;
    const STACK_OF(X509_EXTENSION) *ext_list;
    int num_ext, i;
    long long int computation_result = 0;

    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Start accessing all the data\n");
    
    priv_data_x509 = enc_private_data_file_open(ENC_DO_PRIV_DATA_FILE, bc_ip);

    if (priv_data_x509 == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot access the private data-file of the data-owner\n");
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Before adding openssl details\n");
    
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    
    ext_list = X509_get0_extensions(priv_data_x509);
    num_ext = sk_X509_EXTENSION_num(ext_list);
    
    if(num_ext <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "There is no data in this file to access\n");
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Number of extensions to access in this file is: %d\n", num_ext);
   
    /* The result should be the inner product = 
     * [1 2 3 ... n]*[x1 x2 x3 ... xn] =
     * 1*x1 + 2*x2 + 3*x3 + ... + n*xn */
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Before starting the computation\n");
    
    for (i = 0; i < num_ext; i++) 
    {
        X509_EXTENSION *ext;
        ASN1_OCTET_STRING *value;
        int length;
        const unsigned char *raw_data;
        const unsigned char *actual_data;
        int cur_attbr;

        ext = sk_X509_EXTENSION_value(ext_list, i);
        value = X509_EXTENSION_get_data(ext);
        length = ASN1_STRING_length(value);
        raw_data = ASN1_STRING_get0_data(value);

        /* First two bytes are dummy */
        actual_data = (raw_data + 2);
        length -=2;

        cur_attbr = atoi((const char*)actual_data);

        /* Generate a random number and multiply with it*/
        computation_result += (cur_attbr * (i+1));
    }

    /* Send the computation result to the host */
    ret = (int)computation_result;
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Ended computation after accessing %d attributes\n", num_ext);
exit:
    if (priv_data_x509 != NULL)
    {
        enc_private_data_file_close(priv_data_x509);
    }

    return ret;
}

int ecall_enc_access_all_data(char *result, int *p_result_len, int max_result_sz, in_addr_t bc_ip)
{
    int ret = -1;
    X509* priv_data_x509 = NULL;
    int result_len;
    int enc_result;
    char result_str[12] = {0}; /* Maximum integer can be printed with 11 charecter + one for NULL */

    /* Initialize result with dummy value */
    strncpy(result_str, "0", sizeof("0"));
    *p_result_len = 0;
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Starting to evaluate the eligibility of data-owner for obtaining personal loan\n");
    
    /* Access all data */
    enc_result = enc_access_all_data(bc_ip);
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Result of the computation: %d\n", enc_result);

    /* Convert the result to string */
    itoa(enc_result, result_str, 10);
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "String converted result: %s\n", result_str);

#if 1/* Instead of public-key encyption, use symmetric-key encryption */
    /* +1 is for sending the terminating null charecter as well */
    if (enc_sym_encrypt_result(result_str, (strnlen(result_str, 12) + 1), g_enc_buffer, &result_len) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error while encrypting the result\n");
        goto exit;
    }
#else
    /* +1 is for sending the terminating null charecter as well */
    if (enc_pub_encrypt_result(result_str, (strnlen(result_str, 12) + 1), g_enc_buffer, &result_len) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error while encrypting the result\n");
        goto exit;
    }
#endif
    
    if (max_result_sz < result_len)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Provided buffer is too short for the operation, max_result_sz = %d, result_len = %d\n", max_result_sz, result_len);
        goto exit;
    }
    
    /* Copy to the user buffer */
    memcpy(result, g_enc_buffer, result_len);
    
    *p_result_len = result_len;

    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Returning the encrypted result to the data-owner, having size = %d\n", *p_result_len);
    
    ret = 0;
    
exit:

    return ret;
}
