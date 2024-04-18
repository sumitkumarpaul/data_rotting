#ifndef DATA_ACCESS_H 
#define DATA_ACCESS_H 

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

X509* enc_private_data_file_open(const char* data_file_path);
void enc_private_data_file_close(X509* data_file_X509);
int enc_get_priv_data_val(X509* data_x509, int extension_num, char *return_buf, int *return_len);
int enc_pub_encrypt_result(const char* in_buf, int in_len, char* out_buf, int* p_out_len);
int enc_sym_encrypt_result(const char* in_buf, int in_len, char* out_buf, int* p_out_len);
int enc_check_data_expiry(const char* expiry_time_file);
int enc_get_bc_cur_blk_num();

#define DATA_ID_DOB         0
#define DATA_ID_SSN         1
#define DATA_ID_EDU_LVL     2
#define DATA_ID_DRV_LIC_NO  3
#define DATA_ID_ANL_INCM    4

#endif
