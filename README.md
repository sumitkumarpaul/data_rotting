# ROT: Retention and Operation limitation using TEE
This repository contains all the code and other materials required for TEE based data_rotting mechanisms. This is a test..

# 1. Setup the environment
## 1.1. Setting up compilation environment

## 1.2. Setting up DCAP Attestation Service for Intel SGX
TODO: Check the


# 2. How to compile
A single makefile is required to compile the entire thing

## 2.1 How to compile for normal demonstration purpose

## 2.1 How to compile for measuring performance

# 3. How to run

## 3.1 Compile and run LibEnc

Open a new terminal *(Call it T1)* and issue the following commands:

```
cd libenc;source /opt/intel/sgxsdk/environment;make clean;make; cd -;libenc/libenc 127.0.0.1 1234
```
The following should be shown:

```
rm -f libenc ./src/libenc_main.o ./src/libenc_debug.o ./src/libenc_main.d ./src/libenc_debug.d
cc  -I./src/ -MMD -MP  -c -o src/libenc_main.o src/libenc_main.c
cc  -I./src/ -MMD -MP  -c -o src/libenc_debug.o src/libenc_debug.c
cc  ./src/libenc_main.o ./src/libenc_debug.o -o libenc  
/home/sumit/data_rotting/Implementation/data-rotting
```

## 3.2 Compile and run DataUser in *usage approval* stage

Open another new terminal *(Call it T2)* and issue the following commands:

```
cd data-user;source /opt/intel/sgxsdk/environment;make clean ENC_SRC_NAME=enclave_2_src;make ENC_SRC_NAME=enclave_2_src; cd -;data-user/data-user get-approval 127.0.0.1 1235 127.0.0.1 1234 127.0.0.1 1236

```
The following should be shown:

```
:
g++ -o data-user untrusted_sgx_socket.o entire_enc_u.o ucommon.o data-user-main.o du_debug.o du_enc_mang.o -m64 -O0 -g -L/home/sumit/data_rotting/Implementation/data-rotting/data-user/src/enclave_2_src/sgxssl/Linux/package/lib64 -Wl,--whole-archive -lsgx_usgxssl -Wl,--no-whole-archive -L/opt/intel/sgxsdk/lib64 -lsgx_urts -lsgx_utls -lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto -lpthread -lsgx_uprotected_fs 
cp data-user ../
make[2]: Leaving directory '/home/sumit/data_rotting/Implementation/data-rotting/data-user/src/host'
make[1]: Leaving directory '/home/sumit/data_rotting/Implementation/data-rotting/data-user/src'
mv src/host/data-user .
/home/sumit/data_rotting/Implementation/data-rotting

```

## 3.3 Compile and run DataOwner

Open another new terminal *(Call it T3)* and issue the following commands:

```
cd data-owner;source /opt/intel/sgxsdk/environment;make clean;make; cd -;echo -e \"y\n\" |data-owner/data-owner 127.0.0.1 1235 127.0.0.1 1234 2 materials/sample_do_cert.pem materials/sample_do_enc_sign_pri_key.pem test/test_data_creater/data_cert_discrete/sample_do_data_20_attr.pem 1
```

The following should be the outputs:
```
rm -f data-owner ./src/data-owner-main.o ./src/do_tls_verify_callback.o ./src/do_tls_client.o ./src/do_initial_approval.o ./src/do_common.o ./src/do_tls_err_msg.o ./src/do_data_provision.o ./src/do_debug.o ./src/data-owner-main.d ./src/do_tls_verify_callback.d ./src/do_tls_client.d ./src/do_initial_approval.d ./src/do_common.d ./src/do_tls_err_msg.d ./src/do_data_provision.d ./src/do_debug.d
rm -f ./materials/enc.*
g++ -c -DCLIENT_USE_QVL -m64 -fPIC -Wno-attributes -I. -I/opt/intel/sgxsdk/include -I/usr/include/openssl  -DDEBUG -UNDEBUG -UEDEBUG -std=c++11 -DLOG_LEVEL=DEBUG_LEVEL_ERROR ./src/data-owner-main.c ./src/do_tls_verify_callback.cpp ./src/do_tls_client.cpp ./src/do_initial_approval.c ./src/do_common.c ./src/do_tls_err_msg.cpp ./src/do_data_provision.c ./src/do_debug.c
./src/do_initial_approval.c:208:6: warning: #warning Allowing self signed certificates for the data-users [-Wcpp]
  208 |     #warning Allowing self signed certificates for the data-users
      |      ^~~~~~~
mv *.o ./src/
g++ -o data-owner ./src/data-owner-main.o ./src/do_tls_verify_callback.o ./src/do_tls_client.o ./src/do_initial_approval.o ./src/do_common.o ./src/do_tls_err_msg.o ./src/do_data_provision.o ./src/do_debug.o -m64 -L. -lssl -L/opt/intel/sgxsdk/lib64 -lsgx_urts -lsgx_utls -lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto
/home/sumit/data_rotting/Implementation/data-rotting

Following are the data-requirements asked by data-user:

This uses your dummy personal data issued by the data-issuer to measure the performance of the system:

You need to provide the above-mentioned information to a trusted enclave which will process
these information and computes the inner product of all the provided parameters. We will use enclave(2) from the LibEnc
for this purpose. Apart from this trusted enclave(2), none(including us) will be able to view
your data. Even the trusted enclave will not be able to use the provided data after the expiry
time specified by you. You can know about the details about enclave(2), directly from LibEnc.  

Following is the description of enclave(2), fetched from LibEnc:

This enclave accesses all the data present within the personal information file. This is for performance measurement

Do you agree with it?, please provide a valid answer: [y or n]: 
Do you agree with it?, please provide a valid answer: [y or n]: 



DO: [22-04-2024 16:18:52.610949] Approval-stage start
Succeed.
DO: [22-04-2024 16:18:52.705279] Successfully completed initial approval stage with data-user
DO: [22-04-2024 16:18:54.705376] Starting data-provision stage for the file: test/test_data_creater/data_cert_discrete/sample_do_data_20_attr.pem
Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'
DO: [22-04-2024 16:18:54.867662] Successfully completed data-provision stage

```
Do not worry about, if the following error is shown: 
`Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'`

In the meantime, the following should be shown in the data_user's terminal (i.e., in T2):

```
:
Succeed.
[ENC.] [22-04-2024 16:18:54.898937] Fetched current block number during data provisioning is: 19712085
[ENC.] [22-04-2024 16:18:54.899033] Calculated expiry block number is: 19712090
```

## 3.3 Run DataUser in *Data Usage* stage

Go back to the data_user's terminal *(i.e., in T2)* and issue the following commands:

`data-user/data-user access-data 127.0.0.1 1240`

The following should be shown:


```
:
[ENC.] [22-04-2024 16:19:23.917498] Data is still not expired. Expiry block number is: (19712090) and the current block number is: (19712087)
[ENC.] [22-04-2024 16:19:23.917639] Start-data access
DU: [22-04-2024 16:19:23.918306] Data-user: Stop accessing the sealed-data
DU: [22-04-2024 16:19:23.918320] Data accessed successfully, the result of evaluation is: 20, return from enclave is = 0
```

Then wait for more than 1 minute and issue the same command again:

`data-user/data-user access-data 127.0.0.1 1240`

The following should be shown:

```
data-user/data-user access-data 127.0.0.1 1240
[ENC.] [22-04-2024 16:21:35.641935] Data expired...!! Expiry block number (19712090) is smaller than the current block number (19712098)
[ENC.] [22-04-2024 16:21:35.642212] User provided personal data has expired
[ENC.] [22-04-2024 16:21:35.642294] Problem during opening the data-expiry date related file
[ENC.] [22-04-2024 16:21:35.642320] Cannot access the private data-file of the data-owner
DU: [22-04-2024 16:21:35.642784] Data-user: Stop accessing the sealed-data
DU: [22-04-2024 16:21:35.642797] Data accessed successfully, the result of evaluation is: -1, return from enclave is = 0
```

## 3.4 Clean everything

Go to the LibEnc's terminal (i.e., in T1) and close that (by using ^c command).

To clean all the created materials, issue the following commands in the root directory:

```
cd time-server;make clean; cd -;cd libenc/; make clean; cd -;cd data-owner/; make clean; cd -;cd data-user ;make clean ENC_SRC_NAME=enclave_2_src; cd -
```

## 3.1 Run libenc

## 3.2 Run data user in data procurement mode

## 3.3 Run data owner

## 3.4 Run data user in data access mode

# 4. How to measure performance