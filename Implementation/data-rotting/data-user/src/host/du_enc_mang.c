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

#include "sgx_urts.h"
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "../autogen_src/entire_enc_u.h"
#include "du_enc_mang.h"
#include "du_debug.h"
#include "du_common.h"

#define MAX_PUB_ENC_SK_BUF_SZ 1024

/* Global EID shared by multiple threads */
sgx_enclave_id_t enclave_global_eid = 0;
int du_pub_decrypt_data(EVP_PKEY* pkey, const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len);

char g_du_private_key_file_name[] = "./materials/sample_du_pri_key.pem";
char g_du_public_key_file_name[] = "./materials/sample_du_pub_key.pem";
char g_pub_enc_sk_buff[MAX_PUB_ENC_SK_BUF_SZ];
extern in_addr_t g_bc_ip;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

int du_set_do_cert();

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                print_log(DEBUG_LEVEL_INFO, "Info: %s\n", sgx_errlist[idx].sug);
            print_log(DEBUG_LEVEL_ERROR, "Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        print_log(DEBUG_LEVEL_ERROR, "Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

sgx_status_t initialize_enclave(const char *enclave_path)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	// the 1st parameter should be SERVER_ENCLAVE_FILENAME
	ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL,
				&enclave_global_eid, NULL);

	print_log(DEBUG_LEVEL_INFO, "Server Enc: Enclave library %s\n", enclave_path);

    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return ret;
    }
    return ret;
}

void terminate_enclave()
{
    sgx_destroy_enclave(enclave_global_eid);
    print_log(DEBUG_LEVEL_INFO, "Host: Enclave successfully terminated.\n");
}


int du_setup_enc(const char* enc_path, const char* enc_ip, const char* enc_port, in_addr_t bc_ip)
{
    sgx_status_t result = SGX_SUCCESS;
    int ret = -1;
    int keep_server_up = 0; // should be bool type, 0 false, 1 true
    int cipher_text_size = 0;
    /* Initialize this variable with the size of the output buffer */
    int plain_text_size = 256;
    FILE* fp = NULL;

    print_log(DEBUG_LEVEL_INFO, "Host: Creating the enclave\n");
    result = initialize_enclave(enc_path);
    if (result != SGX_SUCCESS)
    {
        goto exit;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Host: calling setup_tls_server\n");
    
    if(du_set_do_cert() != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot set the public key-certificate of data-owner to the enclave\n");
        goto exit;
    }

    if (fork() == 0)
    {
        /* Child process */
        result = ecall_set_up_tls_server(enclave_global_eid, &ret, enc_port, bc_ip, g_pub_enc_sk_buff, &cipher_text_size, MAX_PUB_ENC_SK_BUF_SZ, keep_server_up);
        
        if (result != SGX_SUCCESS || ret != 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Host: setup_tls_server failed\n");
            goto exit;
        }

        /* Decrypt the symmetric-key with public-key of DU */
        if (du_pub_decrypt(g_pub_enc_sk_buff, cipher_text_size, g_buffer, &plain_text_size) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Decryption of the symmetric-key failed\n");
            goto exit;
        }
   
        fp = fopen(DU_ENC_SYM_KEY_FILE_PATH,"wb");
    
        if(fp == NULL)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during opening the symmetric key file\n");
            goto exit;
        }
    
        if(fwrite(g_buffer, 1, plain_text_size, fp) != plain_text_size)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during writing the decrypted symmetric key to the file\n");
            fclose(fp);
            goto exit;
        }
    
        if (fp != NULL)
        {
            fclose(fp);
        }
 
        /* Child process should exit */
        exit(0);
    }

    ret = 0;
exit:

    return ret;
}

int du_access_do_priv_data(void)
{
    sgx_status_t enc_result = SGX_SUCCESS;
    int encypted_result_sz;
    /* Initialize this variable with the size of the output buffer */
    int ptxt_result_sz = 100;
    int ret = -1;
    char ptxt_result[100] = {0};

    print_log(DEBUG_LEVEL_INFO, "Start accessing the sealed-data\n");
    
    enc_result = initialize_enclave(DU_RCV_SIGNED_ENC_PATH);
    if (enc_result != SGX_SUCCESS)
    {
        goto exit;
    }
  
    print_log(DEBUG_LEVEL_INFO, "Data-user: Start accessing the sealed-data\n");
    
    enc_result = ecall_enc_access_all_data(enclave_global_eid, &ret, g_buffer, &encypted_result_sz, DU_BUF_SZ, g_bc_ip);
    
    if ((enc_result != SGX_SUCCESS) || (ret != 0) || (encypted_result_sz <= 0))
    {
        print_log(DEBUG_LEVEL_ERROR, "Host: Cannot access the data-owner's private data. enc_result = %d, ret = %d, encypted_result_sz = %d, SGX_SUCCESS = %d\n", enc_result, ret, encypted_result_sz, SGX_SUCCESS);
        goto exit;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Data-user: Before decrypting the result\n");
   
    if (du_sym_decrypt(g_buffer, encypted_result_sz, ptxt_result, &ptxt_result_sz) < 0)

    {
        print_log(DEBUG_LEVEL_ERROR, "Host: problem during data-access\n");
        goto exit;
    }

    print_log(DEBUG_LEVEL_ONLY_SPECIAL, "Data-user: Stop accessing the sealed-data\n");
    
    print_log(DEBUG_LEVEL_ONLY_SPECIAL, "Data accessed successfully, the result of evaluation is: %s, return from enclave is = %d\n", ptxt_result, ret);
    
    ret = 0;

exit:
    du_destroy_enc();

    return ret;
}

void du_destroy_enc()
{
    sgx_status_t result = SGX_SUCCESS;
    int dummy = 1;

    print_log(DEBUG_LEVEL_INFO, "Host: calling sample ecall with dummy parameters\n");

    print_log(DEBUG_LEVEL_INFO, "Host: Terminating enclaves\n");

    result = ecall_tear_down_tls_server(enclave_global_eid, &dummy);
    
    if (result != SGX_SUCCESS)
    {
        print_log(DEBUG_LEVEL_ERROR, "Host: Problem during tearing down the server within the enclave..!!\n");
    }

    terminate_enclave();

    return;
}

int du_sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *p_plaintext_len)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len;
    int ret = -1;
    /* Use fixed IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    FILE* fp = NULL;
    char key[32]; /* For hodning 256 bit symmetric-key */
   
    fp = fopen(DU_ENC_SYM_KEY_FILE_PATH,"rb");
    
    if(fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the symmetric-key file\n");
        goto exit;
    }
    
    /* Read 256-bit encryption key */
    if(fread(key, 1, 32, fp) != 32)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during reading the symmetric key\n");
        goto exit;
    }

    *p_plaintext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create context for decryption context\n");
        goto exit;
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot init decryption\n");
        goto exit;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot update decryption\n");
        goto exit;
    }
    
    *p_plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot finalize decryption\n");
        goto exit;
    }
    
    *p_plaintext_len += len;

    ret = 0;

exit:
    /* Clean up */
    if (fp != NULL)
    {
        fclose(fp);
    }

    if (ctx != NULL)
    {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;

}

int du_pub_decrypt(const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    FILE* fp = NULL;
   
    fp = fopen(g_du_private_key_file_name,"rb");
    
    if(fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the data-user's private-key file\n");
        goto exit;
    }
    
    pkey = PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
    
    if (pkey == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Failed to read the private key\n");
        goto exit;
    }

    if (du_pub_decrypt_data(pkey, ctxt, ctxt_len, ptxt, p_ptxt_len) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Problem during the decryption operation\n");
        goto exit;
    }

    ret = 0;

exit:
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

int du_pub_decrypt_data(EVP_PKEY* pkey, const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len)
{
    int ret = -1;

    EVP_PKEY_CTX*ctx = EVP_PKEY_CTX_new(pkey,NULL);

    EVP_PKEY_decrypt_init(ctx);
    
    print_log(DEBUG_LEVEL_INFO, "Data-user: Before calling OpenSSL decryption API\n");
    
    /* On Success, it returns 1 */
    if (EVP_PKEY_decrypt(ctx, ptxt, (size_t *)p_ptxt_len, ctxt, ctxt_len) == 1)
    {
        print_log(DEBUG_LEVEL_INFO, "Plaintext length: %d, plaintext is:\n", *(p_ptxt_len));
        ret = 0;
    }
    else
    {
        print_log(DEBUG_LEVEL_ERROR,"error: decrypt, ctxt_len = %d, ctxt[0] = 0x%X, ctxt[1] = 0x%X, ctxt[2] = 0x%X, ctxt[3] = 0x%X\n", ctxt_len, ctxt[0], ctxt[1], ctxt[2], ctxt[3]);
        print_log(DEBUG_LEVEL_ERROR,"Cipher-text: ctxt[0] = 0x%X, ctxt[1] = 0x%X, ctx[2] = 0x%X, ctxt[3] = 0x%X .. ctxt[last - 3] = 0x%X, ctxt[last -2] = 0x%X, ctxt[last -1] = 0x%X, ctxt[last] = 0x%X\n", ctxt[0], ctxt[1], ctxt[2], ctxt[3], ctxt[ctxt_len - 4], ctxt[ctxt_len - 3], ctxt[ctxt_len - 2], ctxt[ctxt_len - 1]); 
        ERR_print_errors_fp(stderr);
    } 
    
    print_log(DEBUG_LEVEL_INFO, "Data-user: After calling OpenSSL decryption API\n");
    
    EVP_PKEY_CTX_free(ctx);
    
    return ret;
}

int du_pub_encrypt_data(EVP_PKEY* pkey, char* ctxt, int* p_ctxt_len, const char* ptxt, int ptxt_len)
{
    int ret = -1;

    EVP_PKEY_CTX*ctx = EVP_PKEY_CTX_new(pkey,NULL);

    EVP_PKEY_encrypt_init(ctx);
    
    ret = EVP_PKEY_encrypt(ctx, ctxt, (size_t *)p_ctxt_len, ptxt, ptxt_len);

    /* On FAILURE, it returns 0 */
    if(ret == 0){
        print_log(DEBUG_LEVEL_ERROR, "error: encrypt\n");
        ret = -1;
    }else{
        print_log(DEBUG_LEVEL_INFO, "Ciphertext length: %d, ciphertext is:\n", *(p_ctxt_len));
        BIO_dump_fp(stdout,ctxt,(int)*(p_ctxt_len));
        ret = 0;
    } 
    
    EVP_PKEY_CTX_free(ctx);
    
    return ret;
}

int du_set_do_cert()
{
    FILE* fp = NULL;
    int ret = -1;
    int cert_sz;

    fp = fopen(DU_RCV_DO_CERT_PATH,"rb");
    
    if(fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the data-owner's certificate file\n");
        goto exit;
    }
    
    /* Determine the file size */
    fseek(fp, 0L, SEEK_END);
    cert_sz = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if(fread(g_buffer, 1, cert_sz, fp) != cert_sz)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the certificate file of data-owner\n");
        goto exit;
    }

    if(ecall_set_do_cert(enclave_global_eid, g_buffer) != SGX_SUCCESS)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during setting the certificate file of data-owner to the enclave\n");
        goto exit;
    }

    ret = 0;
    print_log(DEBUG_LEVEL_INFO, "Successfully set the data-owner's certificate to the enclave\n");
    
exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

