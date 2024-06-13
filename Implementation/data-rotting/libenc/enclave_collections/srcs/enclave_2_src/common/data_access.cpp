#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/ts.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sgx_tprotected_fs.h>
#include "utility.h"
#include "entire_enc_t.h"
#include "data_access.h"
#include "data_provision.h"
#include "ts_verifier_info.h"
#include "common.h"

int enc_create_socket(char[], in_addr_t bc_ip);
int enc_ssl_recv_data(SSL* ssl, char* data_buf);
int enc_ssl_send_data(SSL* ssl, const char* data_buf, int data_sz);

#define API_KEY 05d0ae97950949cfadb4616a17ac6349
#define BUF_SZ 10240
char data_buf[BUF_SZ];

#define POST_REQUEST_FULL_BLOCK "POST /v3/05d0ae97950949cfadb4616a17ac6349 HTTP/1.1\r\n\
Content-Type:application/json\r\n\
Host:mainnet.infura.io\r\n\
Content-Length:82\r\n\r\n\
{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"latest\",false],\"id\":1}\r\n\r\n"

/* Check details at: https://docs.infura.io/api/networks/ethereum/json-rpc-methods/eth_blocknumber */
#define POST_eth_blockNumber "POST /v3/05d0ae97950949cfadb4616a17ac6349 HTTP/1.1\r\n\
Host:mainnet.infura.io\r\n\
Content-Length:63\r\n\r\n\
{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}\r\n\r\n"


extern int close(int sockfd);

static int enc_trusted_time_comparison(in_addr_t bc_ip);
static int enc_get_trusted_time(time_t *p_cur_trusted_tim);
static int enc_verify_cb(int ok, X509_STORE_CTX *ctx);
static int enc_create_ts_req(char* p_op_buf, int max_req_len, TS_REQ **p_ts_req);
static int enc_verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz, TS_REQ *ts_req, time_t *p_rcvd_ts);
static int enc_connect_to_ts_server(const char* ip, int port);
static in_addr_t inet_addr (const char *cp);
static int inet_aton_end (const char *cp, struct in_addr *addr, const char **endp);
static int enc_send_file(int conn_sock, const char* file_path);
static int enc_recv_file(int conn_sock, const char* file_path);
static int enc_get_ts_resp(char *req_buf, char *resp_buf, int req_sz, int *p_rsp_sz);
static int enc_send_buff_to_file(int conn_sock, char *buff, int buff_size);
static int enc_recv_file_to_buf(int conn_sock, char *buff, int *p_recv_sz, int max_buf_sz);

X509* enc_private_data_file_open(const char* data_file_path, in_addr_t bc_ip)
{
    FILE* fp = NULL;
    int pem_data_sz;
    BIO* certBio = NULL;
    X509* certX509 = NULL;

    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Before expiry verification\n");
    
    if (enc_check_data_expiry(ENC_DO_TIME_LIMIT_FILE, bc_ip) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem during opening the data-expiry date related file\n");
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_ONLY_SPECIAL, "Start-data access\n");
    
    fp = sgx_fopen_auto_key(data_file_path,"rb");

    /* Determine the file size */
    sgx_fseek(fp, 0L, SEEK_END);
    pem_data_sz = sgx_ftell(fp);
    sgx_fseek(fp, 0L, SEEK_SET);

    if(sgx_fread(g_enc_buffer, 1, pem_data_sz, fp) != pem_data_sz)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem during opening the certificate file of data-owner\n");
        goto exit;
    }
    
    certBio = BIO_new_mem_buf((void*)g_enc_buffer, -1); 
    
    if(certBio == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot create the BIO file\n");
        goto exit;
    }

    certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);

    if (certX509 == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot read the BIO file to X509\n");
        goto exit;
    }
  
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "After retrieving the file\n");
exit: 
    if (certBio != NULL)
    {
        BIO_free(certBio);
    }

    if (fp != NULL)
    {
        sgx_fclose(fp);
    }
    
    /* Success case, return from here */
    return certX509;
}

void enc_private_data_file_close(X509* data_file_X509)
{
    if (data_file_X509 != NULL)
    {
        X509_free(data_file_X509);
    }
    
    return;
}

int enc_get_priv_data_val(X509 *data_x509, int extension_num, char *return_buf, int *return_len)
{
    const STACK_OF(X509_EXTENSION) *ext_stk;
    X509_EXTENSION *ext;
    
    *return_len = 0;
    ext_stk = X509_get0_extensions(data_x509);
    
    if (ext_stk == NULL) 
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot extract the extension-stack from x509\n");
        return -1;
    }    

    ext = sk_X509_EXTENSION_value(ext_stk, extension_num);

    if (ext == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot extract the extention number: %d from the extension-stack from x509\n");
        return -1;
    }

    /* First two charecters of ASN1_STRING_get0_data are dummy charecter */
    *return_len = ASN1_STRING_length(X509_EXTENSION_get_data(ext)) - 2;
    memcpy(return_buf, ASN1_STRING_get0_data(X509_EXTENSION_get_data(ext)) + 2, *return_len);

    /* Add ending NULL charecter */
    return_buf[*return_len] = '\0';
    *return_len += 1;
    
    return 0;
}

int enc_pub_encrypt_result(const char* in_buf, int in_len, char* out_buf, int* p_out_len)
{
    int ret = -1;
    FILE* fp = NULL;

    fp = sgx_fopen_auto_key(ENC_DU_CERT_FILE, "rb");

    if(sgx_fread(g_du_cert, 1, CERT_SZ, fp) <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot read the data-user's certificate file\n");
        goto exit;
    }

    if(enc_pub_encrypt(g_du_cert, in_buf, in_len, out_buf, p_out_len) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while encrypting the result of the computation\n");
        goto exit;
    }

    ret = 0;
exit:
    if (fp != NULL)
    {
        sgx_fclose(fp);
    }
     
    return ret;
}

int enc_sym_encrypt_result(const char* in_buf, int in_len, char* out_buf, int* p_out_len)
{
    int ret = -1;
    FILE* fp = NULL;
    unsigned char sym_key[SYM_KEY_SZ];

    fp = sgx_fopen_auto_key(ENC_DU_SYM_KEY_FILE, "rb");

    if(sgx_fread(sym_key, 1, SYM_KEY_SZ, fp) <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot read the previously generated AES-256 symmetric key\n");
        goto exit;
    }

    if(enc_sym_encrypt((unsigned char*)in_buf, in_len, sym_key, (unsigned char*)out_buf, p_out_len) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while encrypting the result of the computation with the symmetric key\n");
        goto exit;
    }

    ret = 0;
exit:
    if (fp != NULL)
    {
        sgx_fclose(fp);
    }
     
    return ret;
}

int enc_check_data_expiry(const char* tim_lim_file, in_addr_t bc_ip)
{
    int ret = -1;
    FILE* fp = NULL;

    fp = sgx_fopen_auto_key(tim_lim_file, "rb");

    if(sgx_fread(g_do_exp_blk_num, 1, EXP_BLK_NUM_STR_SZ, fp) <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot get the expiry time\n");
        goto exit;
    }

    if(enc_trusted_time_comparison(bc_ip) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "User provided personal data has expired\n");
        goto exit;
    }

    ret = 0;
exit:
    if (fp != NULL)
    {
        sgx_fclose(fp);
    }
     
    return ret;
}

static int enc_get_trusted_time(time_t *p_cur_trusted_tim)
{
    TS_REQ *ts_req = NULL;
    int ts_req_len = 0;
    int ts_rsp_len = 0;
    int ret = -1;
    
    ts_req_len = enc_create_ts_req(g_enc_buffer, ENC_BUF_SZ, &ts_req);
    
    if ((ts_req_len <=0) || (ts_req == NULL))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot generate the timestamp request file\n");
        goto exit;
    }

    if (enc_get_ts_resp(g_enc_buffer, g_enc_buffer1, ts_req_len, &ts_rsp_len) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error during getting timestamping response from the trusted-timestamping server\n");
        goto exit;
    }

    if (enc_verify_ts_rsp(g_enc_buffer1, ts_rsp_len, ts_req, p_cur_trusted_tim) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error during verification of the timestamp response\n");
        goto exit;
    }

    ret = 0;
exit:
    if (ts_req != NULL)
    {
        TS_REQ_free(ts_req);
    }

    return ret;
}

static int enc_trusted_time_comparison(in_addr_t bc_ip)
{
    int ret = -1;
    time_t cur_trusted_tim;
    int printed_size;
    int bc_cur_blk_num, bc_exp_blk_num;
    
    /* Get the trusted time from the blockchain */
    bc_cur_blk_num = enc_get_bc_cur_blk_num(bc_ip);
        /* Get the trusted time from the block chain */
    if (bc_cur_blk_num <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot get the current block from the blockchain\n");
    }
    else 
    {
        bc_exp_blk_num = atoi(g_do_exp_blk_num);

        if (bc_cur_blk_num <= bc_exp_blk_num)
        {
            ret = 0;
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Data is still not expired. Expiry block number is: (%ld) and the current block number is: (%ld)\n", bc_exp_blk_num, bc_cur_blk_num);
        }
        else
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Data expired...!! Expiry block number (%ld) is smaller than the current block number (%ld)\n", bc_exp_blk_num, bc_cur_blk_num);
        }
    }

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

    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Creating a time-stamping request\n");

    ts_req = TS_REQ_new();
    
    if (ts_req == NULL)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot allocate a new time-stamp request object\n");
        goto exit;
    }

    /* All the viewed examples used version 1 */
    if (TS_REQ_set_version(ts_req, 1) == 0)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the version to the time-stamp request\n");
        goto exit;
    }

    msg_imprint = TS_MSG_IMPRINT_new();
    
    if (msg_imprint == NULL)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create new message imprint\n");
        goto exit;
    }

    algo = X509_ALGOR_new();

    if (algo == NULL)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create new algo object\n");
        goto exit;
    }

    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(EVP_get_digestbyname("sha1")))) == NULL)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the algorithm\n");
        goto exit;
    }

    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create the parameter object for the algo\n");
        goto exit;
    }
    
    algo->parameter->type = V_ASN1_NULL;

    if (TS_MSG_IMPRINT_set_algo(msg_imprint, algo) != 1)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the algo to the message imprint\n");
        goto exit;
    }
   
    if (TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)dummy_digest, 20) != 1)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the data to the message imprint\n");
        goto exit;
    }
    
    if (TS_REQ_set_msg_imprint(ts_req, msg_imprint) != 1)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the message imprint to the time-stamping request\n");
        goto exit;
    }

    nonce_asn1 = ASN1_INTEGER_new();

    if (nonce_asn1 == NULL)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create asn1 integer for the nonce\n");
        goto exit;
    }

#warning fixit set the nonce
    ASN1_INTEGER_set(nonce_asn1, 0);

    if (TS_REQ_set_nonce(ts_req, nonce_asn1) != 1)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the nonce to the time-stamping request\n");
        goto exit;
    }
    
    der_len = i2d_TS_REQ(ts_req, &p_ts_req_der);
    
    if (der_len <= 0)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot convert the time-response to the DER format\n");
        goto exit;
    }

    if (der_len > max_req_len)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Output buffer cannot hold the time-response buffer\n");
        goto exit;
    }

    if (memcpy(p_op_buf, p_ts_req_der, der_len) != p_op_buf)
    {
       enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during copying data to the output buffer\n");
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
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Verifying a time-stamping response file\n");
    
    if (ts_req ==  NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Time-stamping request is not available\n");
        goto exit;
    }
    
    ts_rsp_bio = BIO_new_mem_buf((void*)ts_rsp_buff, ts_rsp_sz);
    
    if (ts_rsp_bio == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot convert the time-stamp response to a BIO\n");
        goto exit;
    }
    
    ts_resp = d2i_TS_RESP_bio(ts_rsp_bio, &ts_resp);
    
    if (ts_resp ==  NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot obtain the response from the BIO\n");
        goto exit;
    }
    
    /* Create a new verify context from previous request */
    verify_ctx = TS_REQ_to_TS_VERIFY_CTX(ts_req, NULL);
    
    if (verify_ctx == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create the verify context\n");
        goto exit;
    }
    
    /* Prepare verifier related information */
    store_ctx = X509_STORE_new();
    
    if (store_ctx == NULL) 
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create the certificate store context\n");
        goto exit;
    }

    X509_STORE_set_verify_cb(store_ctx, enc_verify_cb);
   
    x509_ca = d2i_X509(NULL, (const unsigned char **)&ts_ca_der_ptr, ts_ca_der_size);

    if (x509_ca == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot read x509 from CA certificate's BIO\n");
        goto exit;
    }

    if (X509_STORE_add_cert(store_ctx, x509_ca) == 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot add the CA certificate to the store\n");
        goto exit;
    }

    if (TS_VERIFY_CTX_set_store(verify_ctx, store_ctx) == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the verifier's information into the verifying context\n");
        goto exit;
    }

    stack_certs = sk_X509_new_null(); 

    if (stack_certs == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create the stack for the certificate\n");
        goto exit;
    }

    x509_signing_cert = d2i_X509(NULL, (const unsigned char **)&ts_signer_der_ptr, ts_signer_der_size);

    if (x509_signing_cert == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot read x509 from singing certificate's BIO\n");
        goto exit;
    }

    if (sk_X509_push(stack_certs, x509_signing_cert) == 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot push the signing certificate to the stack\n");
        goto exit;
    }
   
    if(TS_VERIFY_CTS_set_certs(verify_ctx, stack_certs) == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot set the signing certificate to the verifying context\n");
        goto exit;
    }

    /* Add verifiers information to the verification context */
    if (TS_RESP_verify_response(verify_ctx, ts_resp) == 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Timestamp response verification failed\n");
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Check whether the timestamp server's certificate and timestamp server's ca certificate are in sync..!!\n");
        goto exit;
    }
        
    ts_tst_info = TS_RESP_get_tst_info(ts_resp);

    if (ts_tst_info == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot extract status information from the time-response\n");
        goto exit;
    }
    
    asn1_time = (ASN1_GENERALIZEDTIME*)TS_TST_INFO_get_time(ts_tst_info);
    
    if (asn1_time == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot get the timestamp\n");
        goto exit;
    }

    if (ASN1_TIME_to_tm(asn1_time, &cur_tm) == 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot convert the received timestamp to struct tm\n");
        goto exit;
    }

    if (ocall_mktime(p_rcvd_ts, &cur_tm) != SGX_SUCCESS)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot convert the struct tm to time_t\n");
        goto exit;
    }
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Timestamp response verification passed\n");
    
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

    ts_server_sock = enc_connect_to_ts_server(g_ts_ip, g_ts_port);

    if(ts_server_sock < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem during connection with the timestamping server\n");
        goto exit;
    }

    if(enc_send_buff_to_file(ts_server_sock, req_buf, req_sz) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error while sending the timestamping request to the timestamping-server\n");
        goto exit;
    }

    if(enc_recv_file_to_buf(ts_server_sock, resp_buf, p_rsp_sz, ENC_BUF_SZ) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error while receiving the timestamping response from the timestamping-server\n");
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
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem during socket creation for connecting with: %s:%d\n", ip, port);
        goto error_handling;
    }

    /* Connect with the data-owner */
    ret = connect(srv_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    
    if(ret < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem during connection with data-user(%s:%d)\n", ip, port);
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
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(buff);
    
    if(file_sz < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Receiving file size is < 0\n");
        goto error_handling;
    }
    
    if(file_sz > max_buf_sz)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Receiving file size is more than the maximum buffer-size\n");
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(send(conn_sock, buff, 1, 0) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        //bzero(buff, max_buf_sz);

        cur_recv_sz = recv(conn_sock, &buff[recv_sz], (max_buf_sz - recv_sz), 0);

        if(cur_recv_sz < 0)
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while receiving data for the file: %s\n", buff);
            goto error_handling;
        }

        recv_sz += cur_recv_sz;
    }

    *p_recv_sz = recv_sz;
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Successfully received file having size: %d bytes\n", recv_sz);
    
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
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (recv(conn_sock, l_buff, 1, 0) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != buff_size)
	{
	    ret = send(conn_sock, &buff[send_sz], (buff_size - send_sz), 0);

		if (ret < 0)
		{
 			enc_print_log(ENC_DEBUG_LEVEL_ERROR, "While sending the buffer to a file in receiver-side\n");
			goto error_handling;
		}

        send_sz += ret;
	}

	enc_print_log(ENC_DEBUG_LEVEL_INFO, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
    
    return ret;
}

/* https://elixir.bootlin.com/glibc/latest/source/resolv/inet_addr.c */
static int inet_aton_end (const char *cp, struct in_addr *addr, const char **endp)
{
  static const in_addr_t max[4] = { 0xffffffff, 0xffffff, 0xffff, 0xff };
  in_addr_t val;
  char c;
  union iaddr
  {
    uint8_t bytes[4];
    uint32_t word;
  } res;
  uint8_t *pp = res.bytes;
  int digit;

  int saved_errno = errno;

  res.word = 0;

  c = *cp;
  for (;;)
    {
#if 0/* No error checking */
      /* Collect number up to ``.''.  Values are specified as for C:
	 0x=hex, 0=octal, isdigit=decimal.  */
      if (!isdigit (c))
	goto ret_0;
#endif
      {
	char *endp;
	unsigned long ul = strtoul (cp, &endp, 0);
	if (ul == ULONG_MAX && errno == ERANGE)
	  goto ret_0;
	if (ul > 0xfffffffful)
	  goto ret_0;
	val = ul;
	digit = cp != endp;
	cp = endp;
      }
      c = *cp;
      if (c == '.')
	{
	  /* Internet format:
	     a.b.c.d
	     a.b.c	(with c treated as 16 bits)
	     a.b	(with b treated as 24 bits).  */
	  if (pp > res.bytes + 2 || val > 0xff)
	    goto ret_0;
	  *pp++ = val;
	  c = *++cp;
	}
      else
	break;
    }
#if 0/* No error checking */
  /* Check for trailing characters.  */
  if (c != '\0' && (!isascii (c) || !isspace (c)))
    goto ret_0;
  /*  Did we get a valid digit?  */
  if (!digit)
    goto ret_0;
#endif
  /* Check whether the last part is in its limits depending on the
     number of parts in total.  */
  if (val > max[pp - res.bytes])
    goto ret_0;

  if (addr != NULL)
    addr->s_addr = res.word | htonl (val);
  *endp = cp;

  return 1;

 ret_0:
  return 0;
}


/* ASCII IPv4 Internet address interpretation routine.  The value
   returned is in network order.  */
static in_addr_t inet_addr (const char *cp)
{
  struct in_addr val;
  const char *endp;
  if (inet_aton_end (cp, &val, &endp))
    return val.s_addr;
  return INADDR_NONE;
}

int enc_get_bc_cur_blk_num(in_addr_t bc_ip) {

  char           dest_url[] = "https://mainnet.infura.io";
  BIO              *certbio = NULL;
  X509                *cert = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int ret, i, send_sz;
  char *token;
  int cur_block_num = -1;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0) {
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Could not initialize the OpenSSL library !\n");
  }

  method = TLS_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
  if ( (ctx = SSL_CTX_new(method)) == NULL){
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Unable to create a new SSL context structure.\n");
  }

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
  server = enc_create_socket(dest_url, bc_ip);
  if(server != 0){
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Successfully made the TCP connection to: %s.\n", dest_url);
  }

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, server);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
  if ( SSL_connect(ssl) != 1 ){
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error: Could not build a SSL session to: %s.\n", dest_url);
  }
  else {
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);
  }

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error: Could not get a certificate from: %s.\n", dest_url);
  }
  else {
    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Retrieved the server's certificate from: %s.\n", dest_url);
  }

  /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

  /* Make requests to the Infura */
  send_sz = strlen(POST_eth_blockNumber);
  ret = enc_ssl_send_data(ssl, POST_eth_blockNumber, send_sz);
  enc_print_log(ENC_DEBUG_LEVEL_INFO, "Sending request: %s\n", POST_eth_blockNumber);


  if (ret != send_sz) {
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem during sending the data to the server, return of enc_ssl_send_data: %d, expected: %d\n", ret, send_sz);
  } else {
    memset(data_buf, 0, BUF_SZ);

    if (enc_ssl_recv_data(ssl, data_buf) > 0){
        enc_print_log(ENC_DEBUG_LEVEL_INFO, "Received message(%ld bytes): %s\n", strlen(data_buf), data_buf);
        /* Extract the current block number */
        token = strstr (data_buf,"0x");
        token = strtok (token,"\"");
        cur_block_num = strtol(token, 0, 16);
   
        enc_print_log(ENC_DEBUG_LEVEL_INFO, "Hex representation of the current block-number is: %s, its integer representation is: %ld\n", token, cur_block_num);
    } else {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot receive data from the blockchain!!\n");
    }
  }

  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  SSL_free(ssl);
  close(server);
  X509_free(cert);
  SSL_CTX_free(ctx);
  enc_print_log(ENC_DEBUG_LEVEL_INFO, "Finished SSL/TLS connection with server: %s.\n", dest_url);

  return(cur_block_num);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int enc_create_socket(char url_str[], in_addr_t bc_ip) {
  int sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char      proto[6] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  struct sockaddr_in dest_addr;

  /* ---------------------------------------------------------- *
   * Remove the final / from url_str, if there is one           *
   * ---------------------------------------------------------- */
  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

  /* ---------------------------------------------------------- *
   * the first : ends the protocol string, i.e. http            *
   * ---------------------------------------------------------- */
  strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

  /* ---------------------------------------------------------- *
   * the hostname starts after the "://" part                   *
   * ---------------------------------------------------------- */
  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

  /* ---------------------------------------------------------- *
   * if the hostname contains a colon :, we got a port number   *
   * ---------------------------------------------------------- */
  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
  }

  port = atoi(portnum);

  /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  /* Use ping to findout the IP address of mainnet.infura.io */
  //dest_addr.sin_addr.s_addr = inet_addr("54.160.34.61");
  dest_addr.sin_addr.s_addr = bc_ip;
  enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Set bc_ip: %X\n", bc_ip);


  /* ---------------------------------------------------------- *
   * Zeroing the rest of the struct                             *
   * ---------------------------------------------------------- */
  memset(&(dest_addr.sin_zero), '\0', 8);

  /* ---------------------------------------------------------- *
   * Try to make the host connect here                          *
   * ---------------------------------------------------------- */
  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error: Cannot connect to host %s on port %d.\n",
             hostname, port);
  }

  return sockfd;
}