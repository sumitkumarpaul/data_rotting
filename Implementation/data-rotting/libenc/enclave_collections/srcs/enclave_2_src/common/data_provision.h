#ifndef DATA_PROVISION_H 
#define DATA_PROVISION_H 

#define CERT_SZ                 4096 /* Assuming the upper limit of the certificate size is 4096-bytes */
#define EXP_BLK_NUM_STR_SZ      10   /* This code will support till 9 digit block number which will be more than a century */
#define BC_BLK_TIM              12   /* We are using etherium and for that the the block time is 12 seconds */
#define NONCE_SZ                64
#define SYM_KEY_SZ              32   /* 32-bytes are required for strore AES-256 sym. key  */
#define ENCRYPTED_NONCE_SZ      800 /* The minimum size of the cipher-text in RSA-3072 is 384 bytes (i.e., 3072/8)*/
#define ENC_DO_PRIV_DATA_FILE   "./materials/do_priv_data.sealed" /* This file contains the certified private data of the data owner)*/
#define ENC_DO_TIME_LIMIT_FILE  "./materials/do_tim_lim.sealed" /* This file contains the expiry time of the data owner*/
#define ENC_DU_SYM_KEY_FILE     "./materials/do_sym_key.sealed" /* This file contains the symetric key to be used by DU */
#define ENC_DU_CERT_FILE        "./materials/du_cert.sealed" /* This file contains the expiry time of the data owner*/
#define ENC_DO_PRIV_DATA_FILESZ  204800 /* Checked the size of file having 10000 attributes, it is 203054 bytes, so making this limit 200KB */

extern char g_do_cert[];
extern char g_du_cert[];
extern char g_cur_nonce[];
extern char g_encrypted_cur_nonce[];
extern char g_do_tim_lim[];
extern char g_do_priv_data[];
extern char g_do_exp_blk_num[];

int enc_recv_and_set_du_cert(SSL* ssl, const char* cert_pem);
int enc_pub_encrypt(const char* key_pem, const char* in_buf, int in_len, char* out_buf, int* p_out_len);
int enc_send_encrypted_nonce(const char* do_pubk_pem, SSL* ssl);
int enc_recv_plaintext_nonce(SSL* ssl);
int enc_verify_do_private_data(const unsigned char* di_cert_der, int di_cert_len, const char* do_priv_data);
int enc_seal_data(const char* seal_file, const char *data_buff, int data_size);
int enc_process_data_provision(SSL* ssl, char *pub_enc_sk_buf, int *p_out_len);
int enc_sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, int *p_ciphertext_len);
int enc_sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int *p_plaintext_len);

#endif
