#ifndef DU_ENC_MANG_H 
#define DU_ENC_MANG_H

int du_setup_enc(const char* enc_path, const char* enc_ip, const char* enc_port);
int du_access_do_priv_data();
void du_destroy_enc();
int du_set_do_pubkey();
int du_pub_decrypt(const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len);
int du_sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *p_plaintext_len);

#endif /* DU_ENC_MANG_H */
