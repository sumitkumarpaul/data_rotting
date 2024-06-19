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
#include "openssl_utility.h"
#include "entire_enc_t.h"
#include "data_access.h"
#include "data_provision.h"
#include "common.h"

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
static int enc_create_socket(char[], in_addr_t bc_ip);
static int enc_trusted_time_comparison(in_addr_t bc_ip);

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

static int enc_trusted_time_comparison(in_addr_t bc_ip)
{
    int ret = -1;
    time_t cur_trusted_tim;
    int printed_size;
    int bc_cur_blk_num, bc_exp_blk_num;
    
    bc_cur_blk_num = enc_get_bc_cur_blk_num(bc_ip);

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
static int enc_create_socket(char url_str[], in_addr_t bc_ip) {
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
  dest_addr.sin_addr.s_addr = bc_ip;
  enc_print_log(ENC_DEBUG_LEVEL_INFO, "Set bc_ip: %X\n", bc_ip);


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