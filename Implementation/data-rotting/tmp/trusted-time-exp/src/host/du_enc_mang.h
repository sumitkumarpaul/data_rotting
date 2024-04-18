#ifndef DU_ENC_MANG_H 
#define DU_ENC_MANG_H

int du_setup_enc(const char* enc_path, const char* enc_ip, const char* enc_port);
int du_access_do_priv_data();
void du_destroy_enc();
int du_set_do_pubkey();
int du_decrypt(const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len);

#endif /* DU_ENC_MANG_H */
