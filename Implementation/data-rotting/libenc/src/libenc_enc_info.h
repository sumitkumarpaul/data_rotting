#ifndef LIBENC_ENC_INFO_H 
#define LIBENC_ENC_INFO_H

/* To support more enclaves, this file is to be populated with the proper information */

typedef struct enc_details {
    unsigned int ID; /* Stores the ID of this enclave in the Enclave Library */
    char desc[1024];/* 1024 charecters to write description of the enclave */
    char mrenclave[163];/* Will store in string format, as in the output of sgx_sign dump command */
    char enc_path[1024];/* Store the file-path where this enclave reside */
    char edl_path[1024];/* Store the file-path where the edl file corresponding to the enclave reside */
    char cfg_path[1024];/* Store the file-path where the configuration file of the enclave reside */
    char src_path[1024];/* Store the path where all the source code is stored for this enclave in a zipped format */
} enc_details;

enc_details g_enc_details[] = {
    {
        0,
        "This is actually: Simulated enclave for testing purpose\n",
        "0x91 0x7f 0x54 0x91 0x02 0x11 0x71 0xa9 0xa5 0x30 0x09 0x35 0x1d 0x7d 0xe1 0xb1 \n\
0xf1 0x30 0x31 0xde 0x55 0xf3 0xf3 0x3b 0x0d 0xbd 0x89 0x9e 0x19 0x9f 0xcd 0xd6 \n",/* Do not indent this line */
        "./libenc/enclave_collections/enclaves/enclave_0.so",
        "./libenc/enclave_collections/edls/enclave_0.edl",
        "./libenc/enclave_collections/configs/enclave_0.config.xml",
        "./libenc/enclave_collections/srcs/enclave_0_src.zip"
    },
    {
        1,
        "This is enclave 1, checks the following things:\n\
1. Whether your age is in between 18 and 55\n\
2. Your SSN number is not in block-list\n\
3. Your annual income is more than 50000$\n\
\n",
        "0x49 0xb8 0x9c 0xd5 0x58 0xbc 0x0f 0x0c 0x1e 0x72 0xc8 0x65 0x80 0x93 0x38 0x45 \n\
0xdf 0x8b 0x40 0x29 0x62 0x2a 0x3a 0xde 0x15 0x3c 0xd5 0x24 0xb7 0xf8 0x48 0x33 \n",/* Do not indent this line */
        "./libenc/enclave_collections/enclaves/enclave_1.so",
        "./libenc/enclave_collections/edls/enclave_1.edl",
        "./libenc/enclave_collections/configs/enclave_1.config.xml",
        "./libenc/enclave_collections/srcs/enclave_1_src.zip"
    },
    {
        2,
        "This enclave accesses all the data present within the personal information file. This is for performance measurement\n",
        "0x6e 0x80 0x85 0xb9 0x5a 0xdd 0xc4 0x8c 0xde 0x01 0x2a 0x46 0xd2 0x1b 0xec 0xf4 \n\
0x18 0xd3 0x6e 0xf6 0xaa 0x75 0x8a 0x8c 0xca 0x4e 0x53 0x58 0xa5 0x6f 0x40 0xc8 \n",/* Do not indent this line */
        "./libenc/enclave_collections/enclaves/enclave_2.so",
        "./libenc/enclave_collections/edls/enclave_2.edl",
        "./libenc/enclave_collections/configs/enclave_2.config.xml",
        "./libenc/enclave_collections/srcs/enclave_2_src.zip"
    }
};

char g_libenc_usage_info[] = {
"At this moment, number of available enclave in this library is: 3\n\
- Enclave(0): Performs Operation 0\n\
- Enclave(1): Performs Operation 1\n\
- Enclave(2): Can be used for performance measurement\n\n\
\
At this moment, following commands are available:\n\
- GET-ENC <enclave ID>      :\n\
- GET-EDL <enclave ID>      :\n\
- GET-CNF <enclave ID>      :\n\
- GET-ENC-SZ <enclave ID>   :\n\
- GET-EDL-SZ <enclave ID>   :\n\
- GET-CNF-SZ <enclave ID>   :\n\
- GET-MRENCLAVE <enclave ID>:\n\
- GET-SRC <enclave ID>      : For receiving the zipped form of source code for the specified enclave\n\
- GET-DESC <enclave ID>     :\n"
};

#endif /* LIBENC_ENC_INFO_H */
