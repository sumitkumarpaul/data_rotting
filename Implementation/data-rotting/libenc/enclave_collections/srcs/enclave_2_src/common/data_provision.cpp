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

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sgx_tprotected_fs.h>
#include "../../common/openssl_utility.h"
#include "data_provision.h"
#include "data_access.h"
#include "data_issuer_info.h"

char g_do_cert[CERT_SZ]                         = {0};
char g_du_cert[CERT_SZ]                         = {0};
char g_cur_nonce[NONCE_SZ]                      = {0};
char g_sym_key[SYM_KEY_SZ]                      = {0};
char g_rcvd_nonce[NONCE_SZ]                     = {0};
char g_do_exp_blk_num[EXP_BLK_NUM_STR_SZ]       = {0};
char g_encrypted_cur_nonce[ENCRYPTED_NONCE_SZ]  = {0};
char g_do_priv_data[ENC_DO_PRIV_DATA_FILESZ]    = {0};

extern "C"
{
    void ecall_set_do_cert(const char* cert_pem);
};

void ecall_set_do_cert(const char* cert_pem)
{
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Setting public key-certificate of data-owner\n");

    strncpy(g_do_cert, cert_pem, CERT_SZ);
   
    enc_print_log(ENC_DEBUG_LEVEL_DUMP,  "Data-owner's certificate is:\n%s", g_do_cert);
    
    return;
}

int enc_recv_and_set_du_cert(SSL* ssl, const char* cert_pem)
{
    int ret = -1;

    strncpy(g_do_cert, cert_pem, CERT_SZ);
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Successfully set the public key-certificate of data-user\n");
    
    return ret;
}

int enc_sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int *p_plaintext_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ret = -1;
    /* Use fixed IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    *p_plaintext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create context for decryption context\n");
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
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot init decryption\n");
        goto exit;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot update decryption\n");
        goto exit;
    }
    
    *p_plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot finalize decryption\n");
        goto exit;
    }
    
    *p_plaintext_len += len;

    ret = 0;

exit:

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/* Refer to https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption for details and code example */
int enc_sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, int *p_ciphertext_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ret = -1;
    *p_ciphertext_len = 0;

    /* Use fixed IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create context for encryption context\n");
        goto exit;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot initialize encyption\n");
        goto exit;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot update encyption\n");
        goto exit;
    }
    
    *p_ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot finalize encyption\n");
        goto exit;
    }
    
    *p_ciphertext_len += len;

    ret = 0;
exit:

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int enc_pub_encrypt(const char* cert_pem, const char* in_buf, int in_len, char* out_buf, int* p_out_len)
{
    X509* x509 = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    int ciphertext_len;
    BIO* bio = NULL;
    EVP_PKEY_CTX* ctx = NULL;
        
    bio = BIO_new_mem_buf((void*)cert_pem, -1);
   
    if (bio == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Failed to convert private key buf into BIO_mem\n");
        goto exit;
    }
         
    x509 = PEM_read_bio_X509(bio, &x509, NULL, NULL);
    
    if (x509 == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Failed to convert bio structure to x509 structure\n");
        goto exit;
    }
    
    pkey = X509_get_pubkey(x509);
    
    if (pkey == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Failed to convert bio structure to x509 structure\n");
        goto exit;
    }
    
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    
    if (ctx == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Failed to create pkey context\n");
        goto exit;
    }
    
    EVP_PKEY_encrypt_init(ctx);
   
    /* In the case of failure, this returns 0 */
    if(EVP_PKEY_encrypt(ctx, (unsigned char*)out_buf, (size_t *)p_out_len, (const unsigned char*)in_buf, in_len) == 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Encrypt\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Public-key encryptoin size = %d\n", *p_out_len);
    enc_print_log(ENC_DEBUG_LEVEL_INFO,"After encrytion: ctxt[0] = 0x%X, ctxt[1] = 0x%X, ctxt[2] = 0x%X, ctxt[3] = 0x%X .. ctxt[last - 3] = 0x%X, ctxt[last -2] = 0x%X, ctxt[last -1] = 0x%X, ctxt[last] = 0x%X\n", out_buf[0], out_buf[1], out_buf[2], out_buf[3], out_buf[*p_out_len - 4], out_buf[*p_out_len - 3], out_buf[*p_out_len - 2], out_buf[*p_out_len - 1]);    


    ret = 0;

exit:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    if (x509 != NULL)
    {
        X509_free(x509);
    }

    if (bio != NULL)
    {
        BIO_free(bio);
    }

    return ret;
}


int enc_send_encrypted_nonce(const char* do_pubk_pem, SSL* ssl)
{
    int ret = -1;
    int encrypted_nonce_sz;

    memset(g_cur_nonce, 0, NONCE_SZ);

    /* Create nonce */
    if(sgx_read_rand((unsigned char*)g_cur_nonce, NONCE_SZ) != SGX_SUCCESS)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during creation of nonce\n");
        goto exit;
    }

    /* Encrypt the nonce with Data-owner's public key */
    if(enc_pub_encrypt(do_pubk_pem, g_cur_nonce, NONCE_SZ, g_encrypted_cur_nonce, &encrypted_nonce_sz))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during encrypting the nonce\n");
        goto exit;
    }
    
    /* Send encrypted nonce */
    if(enc_ssl_send_data(ssl, g_encrypted_cur_nonce, encrypted_nonce_sz) <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during sending the encrypted nonce\n");
        goto exit;
    }
    
    if(ENC_LOG_LEVEL >= ENC_DEBUG_LEVEL_DUMP)  
    {
        int i;
        int buf_pos = 0;

        for(i = 0; i < NONCE_SZ; i++)
        {
            buf_pos += snprintf(&g_enc_buffer[buf_pos], ENC_BUF_SZ, "%s%02x", ((i % 16) == 0)? "\n": " ", (g_cur_nonce[i]) & 0xff);
        }
        
        enc_print_log(ENC_DEBUG_LEVEL_DUMP,  "Sent nonce is: %s\n", g_enc_buffer);
    }
    
    ret = 0;    
    
exit:
    return ret;
}

int enc_recv_plaintext_nonce(SSL* ssl)
{
    int ret = -1;
    int rcvd_nonce_sz;

    memset(g_rcvd_nonce, 0, NONCE_SZ);

    /* Receive plain-text nonce from data-owner */
    rcvd_nonce_sz = enc_ssl_recv_data(ssl, g_rcvd_nonce);

    if(rcvd_nonce_sz <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during receiving plaintext-nonce\n");
        goto exit;
    }
    
    /* Compare received nonce with expected value */
    if(strncmp(g_cur_nonce, g_rcvd_nonce, NONCE_SZ) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Received nonce from data-owner, does not match with expected value\n");
        goto exit;
    }
        
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Received expected nonce, successfully verified the data-owner\n");
    
    ret = 0;    

exit:
    return ret;
}

int enc_verify_do_private_data(const unsigned char* di_cert_der, int di_cert_len, const char* do_priv_data)
{
    BIO *do_priv_data_bio       = NULL;
    X509 *do_priv_data_x509     = NULL;
    X509 *di_cert_x509          = NULL;
    X509_STORE *store           = NULL;
    X509_STORE_CTX *verfy_ctx   = NULL;
    int ret = -1;

    /* Initialize to make openssl work */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    do_priv_data_bio = BIO_new_mem_buf((void*)do_priv_data, -1);
    if(do_priv_data_bio == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create a new bio for data-owner's certified data-file\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Created a new bio for data-owner's certified data-file\n");

    store = X509_STORE_new();
    if(store == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create a new store for data-owner's certified data verification\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Created a new store for data-owner's certified data verification\n");
    
    verfy_ctx = X509_STORE_CTX_new();
    if(verfy_ctx == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot create a new store context for data-owner's certified data verification\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Created a new store context for data-owner's certified data verification\n");

    do_priv_data_x509 = PEM_read_bio_X509(do_priv_data_bio, NULL, 0, NULL);
    if(do_priv_data_x509 == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot convert the data-owner's certified data file to X509 structure\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Converted the data-owner's certified data file to X509 structure\n");

    di_cert_x509 = d2i_X509(NULL, &di_cert_der, di_cert_len);
    if(di_cert_x509 == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot convert the data-issuer's certificate to X509 structure\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Convert the data-issuer's certificate to X509 structure\n");

    //TODO: Here verify the subject name as well. It can be taken as input in the ecall

    if(X509_STORE_add_cert(store, di_cert_x509) != 1)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot add the data-issuer's certificate to the store\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Added the data-issuer's certificate to the store\n");

    if(X509_STORE_CTX_init(verfy_ctx, store, do_priv_data_x509, NULL) != 1)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Cannot init the store verification context for verification\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Initialized the store verification context for verification\n");

    if(X509_verify_cert(verfy_ctx) != 1)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Error during data-owner's data verification, it may not be a genuine data\n");
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "First ensure that, DI's information present within data_issuer_info.h is correct\n");
        goto exit;
    }
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Successfully verified the data-owner's data, it is genuine data\n");
    
    ret = 0;

exit:
    if(di_cert_x509 != NULL)
    {
        X509_free(di_cert_x509);
    }
    
    if(do_priv_data_x509 != NULL)
    {
        X509_free(do_priv_data_x509);
    }

    if(verfy_ctx != NULL)
    {
        X509_STORE_CTX_free(verfy_ctx);
    }
    
    if(store != NULL)
    {
        X509_STORE_free(store);
    }
    
    if(do_priv_data_bio != NULL)
    {
        BIO_free(do_priv_data_bio);
    }

    return ret;
}

int enc_seal_data(const char* seal_file, const char *data_buff, int data_size)
{
    int ret = -1;
    int write_ret = -1;
    FILE *fp = NULL;
    int written_sz = 0;

    if (seal_file == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Provided seal-key file is NULL\n");
        goto exit;
    }

    fp = sgx_fopen_auto_key(seal_file, "wb");
    
    if (fp == NULL)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "While creating the seal-file: %s\n", seal_file);
        goto exit;
    }

    while (written_sz < data_size)
    {
        write_ret = sgx_fwrite(&data_buff[written_sz], 1, (data_size - written_sz), fp);

        if (write_ret < 0)
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error during writing operation, only written %d out of %d bytes\n", written_sz, data_size);
            goto exit;
        }

        written_sz += write_ret;
    }

    ret = 0;
exit:
    if (fp != NULL)
    {
        sgx_fclose(fp);
    }

    return ret;
}

int enc_process_data_provision(SSL* ssl, char *pub_enc_sk_buf, int *p_out_len, in_addr_t bc_ip)
{
    int ret = -1;
    int priv_data_sz = 0;
    int cur_bc_blk_num;
    int exp_bc_blk_num;
    char do_tim_lim_str[10];/* The time limit minute could be 10 digit long */
    int do_tim_lim;
   
    /* Receive and seal the data-user's certificate from the data-owner  */
    if(enc_ssl_recv_file(ssl, ENC_DU_CERT_FILE, g_du_cert, NULL) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during receiving the certificate file of the data user\n");
        goto exit;
    }
        
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Received the certificate file of the data user\n");

    /* Receive the time limit */
    if(enc_ssl_recv_data(ssl, do_tim_lim_str) <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during receiving the time limit\n");
        goto exit;
    }

    /* Convert the time limit in terms of seconds */
    do_tim_lim = atoi(do_tim_lim_str) * 60;
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Received time limit of the private data, in terms of second is: %d\n", do_tim_lim);
    
    /* Receive the private data into a file, in memory */
    if(enc_ssl_recv_file(ssl, NULL, g_do_priv_data, &priv_data_sz) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during receiving the file containing the certified private data of the data owner\n");
        goto exit;
    }

    /* Check whether the private data size is more than the buffer size */
    if(priv_data_sz > ENC_DO_PRIV_DATA_FILESZ)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "The size of the receiving data from the data-owner is more than the size of the buffer\n");
        goto exit;
    }
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Received file having size = %d, from data owner, containing certified private data\n", priv_data_sz);
    
    /* Verify whether the received private data file is signed by the trusted data issuer or not */
    if(enc_verify_do_private_data(g_di_certificate, sizeof(g_di_certificate), g_do_priv_data) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during verifying the received private data-file from the data-owner\n");
        goto exit;
    }
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Verified the private data file it is a genuine one\n");

    /* Seal the private data of the data-owner */
    if(enc_seal_data(ENC_DO_PRIV_DATA_FILE, g_do_priv_data, priv_data_sz) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during sealing the data-owner's private data\n");
        goto exit;
    }
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Sealed the data-owner's private data\n");

    /* Get current block number from the blockchain */
    cur_bc_blk_num = enc_get_bc_cur_blk_num(bc_ip);

    if(cur_bc_blk_num <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during fetching the current block number during data provisioning\n");
        goto exit;
    }    

    enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Fetched current block number during data provisioning is: %d\n", cur_bc_blk_num);

    /* Convert the timelimit to the expiry block number */
    exp_bc_blk_num = cur_bc_blk_num + (do_tim_lim / BC_BLK_TIM);

    /* Perform the celing operation */
    if ((do_tim_lim % BC_BLK_TIM) != 0)
    {
        exp_bc_blk_num++;
    }

    /* Save the expiry block number in sealed format */
    itoa(exp_bc_blk_num, g_do_exp_blk_num, 10);

    enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Calculated expiry block number is: %s\n", g_do_exp_blk_num);

    /* Seal the time limit */
    if(enc_seal_data(ENC_DO_TIME_LIMIT_FILE, g_do_exp_blk_num, (strlen(g_do_exp_blk_num) + 1)) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during sealing the data-owner's time limit\n");
        goto exit;
    }
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Sealed the time limit of the private data\n");
    
    /* Create random symetric-key */
    if(sgx_read_rand((unsigned char*)g_sym_key, SYM_KEY_SZ) != SGX_SUCCESS)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during creation of random symetric-key\n");
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Generated random AES-256 symetric-key\n");
   
    /* Seal this newly generated symetric key for later usage */ 
    if(enc_seal_data(ENC_DU_SYM_KEY_FILE, g_sym_key, SYM_KEY_SZ) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during sealing the newly generated AES-256 symetric key\n");
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Sealed the newly generated AES-256 symetric-key\n");
   
    if(enc_pub_encrypt(g_du_cert, g_sym_key, SYM_KEY_SZ, pub_enc_sk_buf, p_out_len) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while encrypting the newly generated symmetric key with the public-key of the data-user\n");
        goto exit;
    }
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Generated symetric-key is encrypted with DU's public key\n");
    
    ret = 0;
    
exit:
    return ret;
}
