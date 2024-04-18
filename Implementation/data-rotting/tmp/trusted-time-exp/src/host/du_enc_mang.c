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
#include <openssl/ts.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include "../autogen_src/entire_enc_u.h"
#include "ts_verifier_info.h"
#include "du_enc_mang.h"
#include "du_debug.h"
#include "du_common.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t enclave_global_eid = 0;
int du_decrypt_data(EVP_PKEY* pkey, const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len);

char g_du_private_key_file_name[] = "./materials/sample_du_pri_key.pem";
char g_du_public_key_file_name[] = "./materials/sample_du_pub_key.pem";

#define ENC_IMPL 1

#if ENC_IMPL
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ENC_BUF_SZ 2048
char g_enc_buffer[ENC_BUF_SZ];
char g_enc_buffer1[ENC_BUF_SZ];

static int enc_send_buff_to_file(int conn_sock, char *buff, int buff_size);
static int enc_recv_file_to_buf(int conn_sock, char *buff, int *p_recv_sz, int max_buf_sz);
static int enc_connect_to_ts_server(const char* ip, int port);
static int enc_get_ts_resp(char *req_buf, char *resp_buf, int req_sz, int *p_rsp_sz);
static int enc_verify_cb(int ok, X509_STORE_CTX *ctx);
static int enc_verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz, TS_REQ *ts_req, time_t *p_rcvd_ts);
static int enc_create_ts_req(char* p_op_buf, int max_req_len, TS_REQ **p_ts_req);
int enc_trusted_time_comparison();
static void enc_get_trusted_time(time_t *p_cur_trusted_tm);
#endif


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

int du_setup_enc(const char* enc_path, const char* enc_ip, const char* enc_port)
{
    sgx_status_t result = SGX_SUCCESS;
    int ret = -1;
    int keep_server_up = 0; // should be bool type, 0 false, 1 true

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
        result = ecall_set_up_tls_server(enclave_global_eid, &ret, enc_port, keep_server_up);
        
        if (result != SGX_SUCCESS || ret != 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Host: setup_tls_server failed\n");
            goto exit;
        }

        /* Child process should exit */
        exit(0);
    }

    /* Parent process */
    //sleep(2);

    ret = 0;
exit:

    return ret;
}

int du_access_do_priv_data(void)
{
    sgx_status_t enc_result = SGX_SUCCESS;
    int encypted_result_sz;
    int ptxt_result_sz;
    int ret = -1;
    char ptxt_result[100] = {0};

    print_log(DEBUG_LEVEL_INFO, "Host: Start accessing the data\n");
    
    enc_result = initialize_enclave(DU_RCV_SIGNED_ENC_PATH);
    if (enc_result != SGX_SUCCESS)
    {
        goto exit;
    }
  
    enc_result = ecall_check_personal_loan_eligibility(enclave_global_eid, &ret, g_buffer, &encypted_result_sz, DU_BUF_SZ);
    
    if ((enc_result != SGX_SUCCESS) || (ret != 0) || (encypted_result_sz <= 0))
    {
        print_log(DEBUG_LEVEL_ERROR, "Host: Cannot access the data-owner's private data. enc_result = %d, ret = %d, encypted_result_sz = %d, SGX_SUCCESS = %d\n", enc_result, ret, encypted_result_sz, SGX_SUCCESS);
        goto exit;
    }
    
    if (du_decrypt(g_buffer, encypted_result_sz, ptxt_result, &ptxt_result_sz) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Host: problem during data-access\n");
        goto exit;
    }

    print_log(DEBUG_LEVEL_INFO, "Data accessed successfully, the result of evaluation is: %s, return from enclave is = %d\n", ptxt_result, ret);

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

#if 0/* This dummy function call is no more required */
    result = enclave_0_ecall_0(enclave_global_eid, &ret, 2, 3);
    if (result != SGX_SUCCESS || ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Host: enclave_0_ecall_0 failed\n");
    }

    print_log(DEBUG_LEVEL_INFO, "Host: Got return from enclave = %d\n", ret);
#endif
    print_log(DEBUG_LEVEL_INFO, "Host: Terminating enclaves\n");

    result = ecall_tear_down_tls_server(enclave_global_eid, &dummy);
    
    if (result != SGX_SUCCESS)
    {
        print_log(DEBUG_LEVEL_ERROR, "Host: Problem during tearing down the server within the enclave..!!\n");
    }

    terminate_enclave();

    return;
}

int du_decrypt(const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len)
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

    if (du_decrypt_data(pkey, ctxt, ctxt_len, ptxt, p_ptxt_len) < 0)
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

int du_decrypt_data(EVP_PKEY* pkey, const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len)
{
    int ret = -1;

    EVP_PKEY_CTX*ctx = EVP_PKEY_CTX_new(pkey,NULL);

    EVP_PKEY_decrypt_init(ctx);
    
    ret = EVP_PKEY_decrypt(ctx, ptxt, (size_t *)p_ptxt_len, ctxt, ctxt_len);

    /* On Success, it returns 1 */
    if(ret == 1){
        print_log(DEBUG_LEVEL_INFO, "Plaintext length: %d, plaintext is:\n", *(p_ptxt_len));
        BIO_dump_fp(stdout,ptxt,(int)*(p_ptxt_len));
        ret = 0;
    }else{
        print_log(DEBUG_LEVEL_ERROR,"error: decrypt\n");
        ret = -1;
    } 
    
    EVP_PKEY_CTX_free(ctx);
    
    return ret;
}

int du_encrypt_data(EVP_PKEY* pkey, char* ctxt, int* p_ctxt_len, const char* ptxt, int ptxt_len)
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

#if ENC_IMPL /* Copy of enclave side implementation */
static void enc_get_trusted_time(time_t *p_cur_trusted_tm)
{
    TS_REQ *ts_req = NULL;
    int ts_req_len = 0;
    int ts_rsp_len = 0;
    int ret = -1;
    
    ts_req_len = enc_create_ts_req(g_enc_buffer, ENC_BUF_SZ, &ts_req);
    
    if ((ts_req_len <=0) || (ts_req == NULL))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot generate the timestamp request file\n");
    }

    /* TODO: Send the request to the time-stamp server and get the response */
    if (enc_get_ts_resp(g_enc_buffer, g_enc_buffer1, ts_req_len, &ts_rsp_len) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during getting timestamping response from the trusted-timestamping server\n");
    }

    if (enc_verify_ts_rsp(g_enc_buffer1, ts_rsp_len, ts_req, p_cur_trusted_tm) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during verification of the timestamp response\n");
    }

    return;
}

int enc_trusted_time_comparison()
{
    int ret = 0;
    time_t cur_trusted_ts;

    /* Get the trusted time */
    enc_get_trusted_time(&cur_trusted_ts);

    print_log(DEBUG_LEVEL_INFO, "Current time-stamp is: %lu\n", cur_trusted_ts);

    return ret;
}

/* TODO: API spec, https://pub.sortix.org/sortix/release/nightly/man/man3/i2d_TS_REQ.3.html */

static int enc_create_ts_req(char* p_op_buf, int max_req_len, TS_REQ **p_ts_req)
{
    /* TODO: Inspired from: https://cpp.hotexamples.com/it/examples/-/-/TS_MSG_IMPRINT_set_algo/cpp-ts_msg_imprint_set_algo-function-examples.html */

    int ret = -1;
    TS_REQ *ts_req = NULL;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    unsigned char *data = NULL;
    ASN1_INTEGER *nonce_asn1 = NULL;
    unsigned char *p_ts_req_der = NULL;
    int der_len = 0;
    
    /* Work with dummy digest */
    char dummy_digest[] = { (char)0x3a, (char)0x30, (char)0x94, (char)0x8f, (char)0x8c, (char)0xd5, (char)0x65, (char)0x5f, (char)0xed, (char)0xe3, (char)0x89, (char)0xd7, (char)0x3b, (char)0x5f, (char)0xec, (char)0xd9, (char)0x12, (char)0x51, (char)0xdf, (char)0x4a };

#warning Fix-this: Returned time-stamp is not correct

   print_log(DEBUG_LEVEL_INFO, "Creating a time-stamping request file\n");

    ts_req = TS_REQ_new();
    
    if (ts_req == NULL)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot allocate a new time-stamp request object\n");
        goto exit;
    }

    /* All the viewed examples used version 1 */
    if (TS_REQ_set_version(ts_req, 1) == 0)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot set the version to the time-stamp request\n");
        goto exit;
    }

    msg_imprint = TS_MSG_IMPRINT_new();
    
    if (msg_imprint == NULL)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot create new message imprint\n");
        goto exit;
    }

    algo = X509_ALGOR_new();

    if (algo == NULL)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot create new algo object\n");
        goto exit;
    }

    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(EVP_get_digestbyname("sha1")))) == NULL)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot set the algorithm\n");
        goto exit;
    }

    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot create the parameter object for the algo\n");
        goto exit;
    }
    
    algo->parameter->type = V_ASN1_NULL;

    if (TS_MSG_IMPRINT_set_algo(msg_imprint, algo) != 1)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot set the algo to the message imprint\n");
        goto exit;
    }
   
    if (TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)dummy_digest, 20) != 1)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot set the data to the message imprint\n");
        goto exit;
    }
    
    if (TS_REQ_set_msg_imprint(ts_req, msg_imprint) != 1)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot set the message imprint to the time-stamping request\n");
        goto exit;
    }

    nonce_asn1 = ASN1_INTEGER_new();

    if (nonce_asn1 == NULL)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot create asn1 integer for the nonce\n");
        goto exit;
    }

#warning fixit set the nonce
    ASN1_INTEGER_set(nonce_asn1, 0);

    if (TS_REQ_set_nonce(ts_req, nonce_asn1) != 1)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot set the nonce to the time-stamping request\n");
        goto exit;
    }
    
    der_len = i2d_TS_REQ(ts_req, &p_ts_req_der);
    
    if (der_len <= 0)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Cannot convert the time-response to the DER format\n");
        goto exit;
    }

    if (der_len > max_req_len)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Output buffer cannot hold the time-response buffer\n");
        goto exit;
    }

    if (memcpy(p_op_buf, p_ts_req_der, der_len) != p_op_buf)
    {
       print_log(DEBUG_LEVEL_ERROR,  "Problem during copying data to the output buffer\n");
        goto exit;
    }

    ret = der_len;

    *p_ts_req = ts_req;

exit:
    if (p_ts_req_der != NULL)
    {
        OPENSSL_free(p_ts_req_der);
    }

    if (nonce_asn1  != NULL)
    {
        ASN1_INTEGER_free(nonce_asn1);
    }

    if (algo != NULL)
    {
        X509_ALGOR_free(algo);
    }

    if (msg_imprint != NULL)
    {
        TS_MSG_IMPRINT_free(msg_imprint);
    }
    
    return ret;
}

static int enc_verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz, TS_REQ *ts_req, time_t *p_rcvd_ts)
{
    /* https://cpp.hotexamples.com/it/examples/-/-/TS_RESP_verify_response/cpp-ts_resp_verify_response-function-examples.html */

    int ret = -1;
    unsigned char* ts_ca_der_ptr = g_ts_ca_cert_buff;
    unsigned char* ts_signer_der_ptr = g_ts_signer_cert_buff;
    int ts_ca_der_size = sizeof(g_ts_ca_cert_buff);
    int ts_signer_der_size = sizeof(g_ts_signer_cert_buff);
    TS_RESP *ts_resp = NULL;
    BIO *ts_rsp_bio = NULL;
    TS_VERIFY_CTX *verify_ctx = NULL;
    X509_STORE *store_ctx = NULL;
    X509 *x509_ca = NULL;
    X509 *x509_signing_cert = NULL;
    STACK_OF(X509) *stack_certs = NULL;
    TS_TST_INFO *ts_tst_info = NULL;
    ASN1_GENERALIZEDTIME *asn1_time = NULL;
    struct tm cur_tm;
   
   /* Copy the time-stamping request response to buffer */ 
    print_log(DEBUG_LEVEL_INFO, "Verifying a time-stamping response file\n");
    
    if (ts_req ==  NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Time-stamping request is not available\n");
        goto exit;
    }
    
    ts_rsp_bio = BIO_new_mem_buf((void*)ts_rsp_buff, ts_rsp_sz);
    
    if (ts_rsp_bio == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot convert the time-stamp response to a BIO\n");
        goto exit;
    }
    
    ts_resp = d2i_TS_RESP_bio(ts_rsp_bio, &ts_resp);
    
    if (ts_resp ==  NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot obtain the response from the BIO\n");
        goto exit;
    }
    
    /* Create a new verify context from previous request */
    verify_ctx = TS_REQ_to_TS_VERIFY_CTX(ts_req, NULL);
    
    if (verify_ctx == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the verify context\n");
        goto exit;
    }
    
    /* Prepare verifier related information */
    store_ctx = X509_STORE_new();
    
    if (store_ctx == NULL) 
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the certificate store context\n");
        goto exit;
    }

    X509_STORE_set_verify_cb(store_ctx, enc_verify_cb);
   
    x509_ca = d2i_X509(NULL, (const unsigned char **)&ts_ca_der_ptr, ts_ca_der_size);

    if (x509_ca == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot read x509 from CA certificate's BIO\n");
        goto exit;
    }

    if (X509_STORE_add_cert(store_ctx, x509_ca) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot add the CA certificate to the store\n");
        goto exit;
    }

    if (TS_VERIFY_CTX_set_store(verify_ctx, store_ctx) == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the verifier's information into the verifying context\n");
        goto exit;
    }

    stack_certs = sk_X509_new_null(); 

    if (stack_certs == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the stack for the certificate\n");
        goto exit;
    }

    x509_signing_cert = d2i_X509(NULL, (const unsigned char **)&ts_signer_der_ptr, ts_signer_der_size);

    if (x509_signing_cert == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot read x509 from singing certificate's BIO\n");
        goto exit;
    }

    if (sk_X509_push(stack_certs, x509_signing_cert) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot push the signing certificate to the stack\n");
        goto exit;
    }
   
    if(TS_VERIFY_CTS_set_certs(verify_ctx, stack_certs) == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the signing certificate to the verifying context\n");
        goto exit;
    }

    /* Add verifiers information to the verification context */
    if (TS_RESP_verify_response(verify_ctx, ts_resp) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Timestamp response verification failed\n");
        print_log(DEBUG_LEVEL_ERROR,  "Check whether the timestamp server's certificate and timestamp server's ca certificate are in sync..!!\n");
        goto exit;
    }
        
    ts_tst_info = TS_RESP_get_tst_info(ts_resp);

    if (ts_tst_info == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot extract status information from the time-response\n");
        goto exit;
    }
    
    asn1_time = TS_TST_INFO_get_time(ts_tst_info);
    
    if (asn1_time == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot get the timestamp\n");
        goto exit;
    }

    if (ASN1_TIME_to_tm(asn1_time, &cur_tm) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot convert the received timestamp to struct tm\n");
        goto exit;
    }

    *p_rcvd_ts = mktime(&cur_tm);
    
    print_log(DEBUG_LEVEL_INFO,  "Timestamp response verification passed\n");
    
    ret = 0;

exit:
#if 0/* Free operation causes segmentation fault*/
    if (stack_certs != NULL)
    {
        sk_X509_pop_free(stack_certs, X509_free);
    }
#endif

    if (x509_signing_cert != NULL)
    {
        X509_free(x509_signing_cert);
    }

    if (x509_ca != NULL)
    {
        X509_free(x509_ca);
    }

#if 0/* Free operation causes segmentation fault*/
    if (store_ctx != NULL)
    {
        X509_STORE_free(store_ctx);
    }
#endif
    
    if (verify_ctx != NULL)
    {
        TS_VERIFY_CTX_free(verify_ctx);
    }
    
    if (ts_rsp_bio != NULL)
    {
        BIO_free_all(ts_rsp_bio);
    }

    if (ts_resp != NULL)
    {
        TS_RESP_free(ts_resp);
    }
    
    return ret;
}

static int enc_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    return ok;
}

static int enc_get_ts_resp(char *req_buf, char *resp_buf, int req_sz, int *p_rsp_sz)
{
    int ret = -1;
    int ts_server_sock = -1;

#warning take these inputs from user
    ts_server_sock = enc_connect_to_ts_server("127.0.0.1", 1240);

    if(ts_server_sock < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during connection with the timestamping server\n");
        goto exit;
    }

    if(enc_send_buff_to_file(ts_server_sock, req_buf, req_sz) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while sending the timestamping request to the timestamping-server\n");
        goto exit;
    }

    if(enc_recv_file_to_buf(ts_server_sock, resp_buf, p_rsp_sz, ENC_BUF_SZ) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while receiving the timestamping response from the timestamping-server\n");
        goto exit;
    }

    ret = 0;

exit:
    if(ts_server_sock >= 0)
    {
        close(ts_server_sock);
    }

    return ret;
}

/* Establish connection with the time-stamping server */
static int enc_connect_to_ts_server(const char* ip, int port)
{
    int ret = -1;
    int srv_sock;
    struct sockaddr_in srv_addr;

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = inet_addr(ip);

    srv_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(srv_sock < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during socket creation for connecting with: %s:%d\n", ip, port);
        goto error_handling;
    }

    /* Connect with the data-owner */
    ret = connect(srv_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    
    if(ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during connection with data-user(%s:%d)\n", ip, port);
        goto error_handling;
    }

    return srv_sock;

error_handling:
    if (srv_sock > 0)
    {
        close(srv_sock);
    }

    return ret;
}

static int enc_recv_file_to_buf(int conn_sock, char *buff, int *p_recv_sz, int max_buf_sz)
{
    int ret = -1;
    int cur_recv_sz;
    int file_sz;
    int recv_sz;

    /* Size should not be more than 20 charecter long */
    bzero(buff, 20);

    /* First read the file size */
    if(recv(conn_sock, buff, 20, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(buff);
    
    if(file_sz < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Receiving file size is < 0\n");
        goto error_handling;
    }
    
    if(file_sz > max_buf_sz)
    {
        print_log(DEBUG_LEVEL_ERROR, "Receiving file size is more than the maximum buffer-size\n");
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(send(conn_sock, buff, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        bzero(buff, max_buf_sz);

        cur_recv_sz = recv(conn_sock, &buff[recv_sz], (max_buf_sz - recv_sz), 0);

        if(cur_recv_sz < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem while receiving data for the file: %s\n", buff);
            goto error_handling;
        }

        recv_sz += cur_recv_sz;
    }

    *p_recv_sz = recv_sz;
    
    print_log(DEBUG_LEVEL_INFO, "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = 0;

error_handling:

    return ret;
}

static int enc_send_buff_to_file(int conn_sock, char *buff, int buff_size)
{
	int ret = -1;
	int str_sz;
	int send_sz;
    char l_buff[50];

    /* File size should not more than 20 charecte long */
	bzero(l_buff, 20);

    /* Convert the file-size to string */
    str_sz = snprintf(l_buff, 20, "%d", buff_size);

    if (send(conn_sock, l_buff, (str_sz + 1), 0) != (str_sz + 1))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (recv(conn_sock, l_buff, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != buff_size)
	{
	    ret = send(conn_sock, &buff[send_sz], (buff_size - send_sz), 0);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending the buffer to a file in receiver-side\n");
			goto error_handling;
		}

        send_sz += ret;
	}

	print_log(DEBUG_LEVEL_INFO, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
    
    return ret;
}

#else

TS_REQ *g_ts_req = NULL;

/* TODO: API spec, https://pub.sortix.org/sortix/release/nightly/man/man3/i2d_TS_REQ.3.html */

int create_ts_req(const char* ts_req_file)
{
    /* TODO: Inspired from: https://cpp.hotexamples.com/it/examples/-/-/TS_MSG_IMPRINT_set_algo/cpp-ts_msg_imprint_set_algo-function-examples.html */

    int ret = -1;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    int der_len = 0;
    unsigned char *data = NULL;
    ASN1_INTEGER *nonce_asn1 = NULL;
    FILE* fp = NULL;
    unsigned char *p_ts_req_der = NULL;
    
    /* Work with dummy digest */
    char dummy_digest[] = { 0x3a, 0x30, 0x94, 0x8f, 0x8c, 0xd5, 0x65, 0x5f, 0xed, 0xe3, 0x89, 0xd7, 0x3b, 0x5f, 0xec, 0xd9, 0x12, 0x51, 0xdf, 0x4a };

#warning Fix-this: Returned time-stamp is not correct

    print_log(DEBUG_LEVEL_INFO, "Creating a time-stamping request file\n");

    g_ts_req = TS_REQ_new();
    
    if (g_ts_req == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot allocate a new time-stamp request object\n");
        goto exit;
    }

    /* All the viewed examples used version 1 */
    if (TS_REQ_set_version(g_ts_req, 1) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the version to the time-stamp request\n");
        goto exit;
    }

    msg_imprint = TS_MSG_IMPRINT_new();
    
    if (msg_imprint == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create new message imprint\n");
        goto exit;
    }

    algo = X509_ALGOR_new();

    if (algo == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create new algo object\n");
        goto exit;
    }

    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(EVP_get_digestbyname("sha1")))) == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the algorithm\n");
        goto exit;
    }

    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the parameter object for the algo\n");
        goto exit;
    }
    
    algo->parameter->type = V_ASN1_NULL;

    if (TS_MSG_IMPRINT_set_algo(msg_imprint, algo) != 1)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the algo to the message imprint\n");
        goto exit;
    }
   
    if (TS_MSG_IMPRINT_set_msg(msg_imprint, dummy_digest, 20) != 1)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the data to the message imprint\n");
        goto exit;
    }
    
    if (TS_REQ_set_msg_imprint(g_ts_req, msg_imprint) != 1)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the message imprint to the time-stamping request\n");
        goto exit;
    }

    nonce_asn1 = ASN1_INTEGER_new();

    if (nonce_asn1 == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create asn1 integer for the nonce\n");
        goto exit;
    }

#warning fixit set the nonce
    ASN1_INTEGER_set(nonce_asn1, 0);

    if (TS_REQ_set_nonce(g_ts_req, nonce_asn1) != 1)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the nonce to the time-stamping request\n");
        goto exit;
    }
    
    fp = fopen(ts_req_file, "wb");

    if (fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot open the file for writing the time-stamping request\n");
        goto exit;
    }
   
    der_len = i2d_TS_REQ(g_ts_req, &p_ts_req_der);
    
    if (der_len <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot convert the time-response to the DER format\n");
        goto exit;
    }

    if (fwrite(p_ts_req_der, 1, der_len, fp) != der_len)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Problem during the write operation to the file\n");
        goto exit;
    }
    
    print_log(DEBUG_LEVEL_INFO,  "Successfully generated timestamp request file: %s\n", ts_req_file);

    ret = 0;

exit:
    if (p_ts_req_der != NULL)
    {
        OPENSSL_free(p_ts_req_der);
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

    if (nonce_asn1  != NULL)
    {
        ASN1_INTEGER_free(nonce_asn1);
    }

    if (algo != NULL)
    {
        X509_ALGOR_free(algo);
    }

    if (msg_imprint != NULL)
    {
        TS_MSG_IMPRINT_free(msg_imprint);
    }

#if 0
    if (ts_req != NULL)
    {
        TS_REQ_free(ts_req);
    }
#endif

    return ret;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    return ok;
}


int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
	{
	static const int min[9]={ 0, 0, 1, 1, 0, 0, 0, 0, 0};
	static const int max[9]={99, 99,12,31,23,59,59,12,59};
	char *a;
	int n,i,l,o;

	if (d->type != V_ASN1_GENERALIZEDTIME) return(0);
	l=d->length;
	a=(char *)d->data;
	o=0;
	/* GENERALIZEDTIME is similar to UTCTIME except the year is
         * represented as YYYY. This stuff treats everything as a two digit
         * field so make first two fields 00 to 99
         */
	if (l < 13) goto err;
	for (i=0; i<7; i++)
		{
		if ((i == 6) && ((a[o] == 'Z') ||
			(a[o] == '+') || (a[o] == '-')))
			{
			i++;
			if (tm)
				tm->tm_sec = 0;
			break;
			}
		if ((a[o] < '0') || (a[o] > '9')) goto err;
		n= a[o]-'0';
		if (++o > l) goto err;

		if ((a[o] < '0') || (a[o] > '9')) goto err;
		n=(n*10)+ a[o]-'0';
		if (++o > l) goto err;

		if ((n < min[i]) || (n > max[i])) goto err;
		if (tm)
			{
			switch(i)
				{
			case 0:
				tm->tm_year = n * 100 - 1900;
				break;
			case 1:
				tm->tm_year += n;
				break;
			case 2:
				tm->tm_mon = n - 1;
				break;
			case 3:
				tm->tm_mday = n;
				break;
			case 4:
				tm->tm_hour = n;
				break;
			case 5:
				tm->tm_min = n;
				break;
			case 6:
				tm->tm_sec = n;
				break;
				}
			}
		}
	/* Optional fractional seconds: decimal point followed by one
	 * or more digits.
	 */
	if (a[o] == '.')
		{
		if (++o > l) goto err;
		i = o;
		while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
			o++;
		/* Must have at least one digit after decimal point */
		if (i == o) goto err;
		}

	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-'))
		{
		int offsign = a[o] == '-' ? -1 : 1, offset = 0;
		o++;
		if (o+4 > l) goto err;
		for (i=7; i<9; i++)
			{
			if ((a[o] < '0') || (a[o] > '9')) goto err;
			n= a[o]-'0';
			o++;
			if ((a[o] < '0') || (a[o] > '9')) goto err;
			n=(n*10)+ a[o]-'0';
			if ((n < min[i]) || (n > max[i])) goto err;
			if (tm)
				{
				if (i == 7)
					offset = n * 3600;
				else if (i == 8)
					offset += n * 60;
				}
			o++;
			}
		if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
			return 0;
		}
	else if (a[o])
		{
		/* Missing time zone information. */
		goto err;
		}
	return(o == l);
err:
	return(0);
	}


int verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz)
{
    /* https://cpp.hotexamples.com/it/examples/-/-/TS_RESP_verify_response/cpp-ts_resp_verify_response-function-examples.html */

    int ret = -1;
    unsigned char* ts_ca_der_ptr = g_ts_ca_cert_buff;
    unsigned char* ts_signer_der_ptr = g_ts_signer_cert_buff;
    int ts_ca_der_size = sizeof(g_ts_ca_cert_buff);
    int ts_signer_der_size = sizeof(g_ts_signer_cert_buff);
    TS_RESP *ts_resp = NULL;
    BIO *ts_rsp_bio = NULL;
    TS_VERIFY_CTX *verify_ctx = NULL;
    X509_STORE *store_ctx = NULL;
    X509 *x509_ca = NULL;
    X509 *x509_signing_cert = NULL;
    STACK_OF(X509) *stack_certs = NULL;
    TS_STATUS_INFO *ts_sts_info = NULL;
    ASN1_GENERALIZEDTIME *asn1_time = NULL;
    struct tm time_val;
    BIO *time_print_bio = NULL;
   
   /* Copy the time-stamping request response to buffer */ 
    print_log(DEBUG_LEVEL_INFO, "Verifying a time-stamping response file\n");
    
    if (g_ts_req ==  NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Time-stamping request is not available\n");
        goto exit;
    }
    
    ts_rsp_bio = BIO_new_mem_buf((void*)ts_rsp_buff, ts_rsp_sz);
    
    if (ts_rsp_bio == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot convert the time-stamp response to a BIO\n");
        goto exit;
    }
    
    ts_resp = d2i_TS_RESP_bio(ts_rsp_bio, &ts_resp);
    
    if (ts_resp ==  NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot obtain the response from the BIO\n");
        goto exit;
    }
    
    /* Create a new verify context from previous request */
    verify_ctx = TS_REQ_to_TS_VERIFY_CTX(g_ts_req, NULL);
    
    if (verify_ctx == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the verify context\n");
        goto exit;
    }
    
    /* Prepare verifier related information */
    store_ctx = X509_STORE_new();
    
    if (store_ctx == NULL) 
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the certificate store context\n");
        goto exit;
    }

    X509_STORE_set_verify_cb(store_ctx, verify_cb);
   
    x509_ca = d2i_X509(NULL, (const unsigned char **)&ts_ca_der_ptr, ts_ca_der_size);

    if (x509_ca == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot read x509 from CA certificate's BIO\n");
        goto exit;
    }

    if (X509_STORE_add_cert(store_ctx, x509_ca) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot add the CA certificate to the store\n");
        goto exit;
    }

    if (TS_VERIFY_CTX_set_store(verify_ctx, store_ctx) == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the verifier's information into the verifying context\n");
        goto exit;
    }

    stack_certs = sk_X509_new_null(); 

    if (stack_certs == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot create the stack for the certificate\n");
        goto exit;
    }

    x509_signing_cert = d2i_X509(NULL, (const unsigned char **)&ts_signer_der_ptr, ts_signer_der_size);

    if (x509_signing_cert == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot read x509 from singing certificate's BIO\n");
        goto exit;
    }

    if (sk_X509_push(stack_certs, x509_signing_cert) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot push the signing certificate to the stack\n");
        goto exit;
    }
   
    if(TS_VERIFY_CTS_set_certs(verify_ctx, stack_certs) == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot set the signing certificate to the verifying context\n");
        goto exit;
    }

    /* Add verifiers information to the verification context */

    if (TS_RESP_verify_response(verify_ctx, ts_resp) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Timestamp response verification failed\n");
        print_log(DEBUG_LEVEL_ERROR,  "Check whether the timestamp server's certificate and timestamp server's ca certificate are in sync..!!\n");
        goto exit;
    }
        
    ts_sts_info = TS_RESP_get_status_info(ts_resp);

    if (ts_sts_info == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot extract status information from the time-response\n");
        goto exit;
    }

    asn1_time = TS_TST_INFO_get_time(ts_sts_info);
    
    if (asn1_time == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot get the timestamp\n");
        goto exit;
    }

    time_print_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (time_print_bio == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot open the timestamp bio for printing\n");
        goto exit;
    }
    
    print_log(DEBUG_LEVEL_INFO,  "Timestamp response verification passed\n");
#warning Cannot parse the timestamp string yet
#if 0
    if (asn1_generalizedtime_to_tm(&time_val, asn1_time) == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Cannot parse the returned timestamp to struct tm\n");
        goto exit;
    }
    print_log(DEBUG_LEVEL_INFO,  "Line: %d\n", __LINE__);

    print_log(DEBUG_LEVEL_INFO,  "Timestamp response verification passed, timestamp is: \n");

    //ASN1_GENERALIZEDTIME_print(time_print_bio, asn1_time);
    //ASN1_TIME_print(time_print_bio, asn1_time);
    
    print_log(DEBUG_LEVEL_INFO,  "\n");
    
    BIO_free(time_print_bio);
#endif
    ret = 0;

exit:
#if 0/* Free operation causes segmentation fault*/
    if (stack_certs != NULL)
    {
        sk_X509_pop_free(stack_certs, X509_free);
    }
#endif

    if (x509_signing_cert != NULL)
    {
        X509_free(x509_signing_cert);
    }

    if (x509_ca != NULL)
    {
        X509_free(x509_ca);
    }

#if 0/* Free operation causes segmentation fault*/
    if (store_ctx != NULL)
    {
        X509_STORE_free(store_ctx);
    }
#endif
    
    if (verify_ctx != NULL)
    {
        TS_VERIFY_CTX_free(verify_ctx);
    }
    
    if (ts_rsp_bio != NULL)
    {
        BIO_free_all(ts_rsp_bio);
    }

    if (ts_resp != NULL)
    {
        TS_RESP_free(ts_resp);
    }
    
    if (g_ts_req != NULL)
    {
        TS_REQ_free(g_ts_req);
        g_ts_req = NULL;
    }
    
    return ret;
}

#endif
