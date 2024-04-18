#ifndef DU_COMMON_H
#define DU_COMMON_H

#define DU_BUF_SZ                   204800
#define DU_RCV_SIGNED_ENC_PATH      "./materials/rcvd_enc.sign.so"
#define DU_RCV_DO_CERT_PATH         "./materials/do.pem"
#define DU_RCV_EDL_FILE_PATH        "./materials/enc.edl"
#define DU_ENC_SYM_KEY_FILE_PATH    "./materials/pub_enc_sym_key_file.key"
#define DU_CERT_FILE_PATH           "./materials/sample_du_cert.pem"

extern char g_buffer[];
extern char *g_ts_ip;
extern int  g_ts_port;

#endif /* DU_COMMON_H */
