# ROT: Retention and Operation limitation using TEE
This repository contains the prototype implementation of the $ROT$, which provides *Retention and Operation limitation of private data using TEE*.

The involved parties in $ROT$ are, a data-owner ($DO$), a data-user ($DU$) and a trusted library ($Lib_{Enc}$). Only $DU$ requires an environment having support of the, Trusted Execution Environment (TEE) and others do not require TEE. **Intel-SGX** is used as the underlying TEE. Specifically, for performing all our development, experimentation and performance measurement purpose, we use an SGX-enabled instance, [DC4SV3](https://learn.microsoft.com/en-us/azure/virtual-machines/dcv3-series) in Microsoft Azure cloud. We use **Ubuntu-20.04** Operating System, in that environment. $ROT$ is mainly implemented in ***C*** and ***C++***-programming languages. This implementation is dependent on [Intel-SGX-SDK](https://github.com/intel/linux-sgx). 

## 1. How to create the system?
Intel-SGX enabled VM can be created in Microsoft-Azure, by following [this guide line](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal). After creating the system, enable the remote attestation by following [this link](https://learn.microsoft.com/en-us/azure/attestation/quickstart-powershell). This [text](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management) might also be useful.

If you already have a SGX-enabled system, then this step is not required.

## 2. How to prepare the system?
A simple working environment can be created by running all the involved parties (i.e., $DO$, $Lib_{Enc}$ and $DU$) on the same enviroment and enable communication among themselves using local loopback interface. However, internet reachability of is required for the environment, for the blockchain access and the proper working of remote-attestation procedure.

### 2.1. Install Intel-SGX-SDK
$ROT$ is developed using *Intel-SGX-SDK version: 2.21.100.1*. It can be compiled from its source code of prover version and installed in the new system by following [this guide](https://github.com/intel/linux-sgx). Or, its pre-built binary installer can be downloaded from [here](https://download.01.org/intel-sgx/sgx-linux/2.21/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.21.100.1.bin).

***Note:*** If you are using the pre-built binary, then you need to install a few supporting software using the following command.

```
sudo apt-get update
sudo apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
```

### 2.2. Install Intel-SGX platform software
Required platform packages must be installed from a local repo in the system. This local repo can be created by compiling its source code according to this [information](https://github.com/intel/linux-sgx?tab=readme-ov-file#build-the-intelr-sgx-psw-and-intelr-sgx-psw-installer). Alternatively, pre-built repo can be downloaded from [here](https://download.01.org/intel-sgx/sgx-linux/2.21/distro/ubuntu20.04-server/sgx_debian_local_repo.tgz).

Then add the local repo to the system repository configuration, append the following line to /etc/apt/sources.list. You need to replace PATH_TO_LOCAL_REPO with the proper path on your system:

```
deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO focal main
```
Then issue the following commands to install the *psw* packages.
```
sudo apt-get update
sudo apt-get install -y libsgx-launch libsgx-urts libsgx-quote-ex libsgx-dcap-ql
```

### 2.3. Setup DCAP
Then fetch the required certificates from Intel issue the following commands:
```
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null
wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt update
sudo apt-get install libsgx-dcap-default-qpl
```
$ROT$ uses, Intel-Data Center Attestation Primitives, Intel-DCAP. If you are using Microsoft Azure, then use [this guide](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management#how-do-i-use-intel-qpl-with-trusted-hardware-identity-management) to setup DCAP. In other Intel-SGX environment, you may refer [this](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html).

### 2.4. Verify installation and setup

Before proceeding further, it is now important to verify that everything setup till now are fine. Specifically, it is important to ensure that an *enclave* can run in the system in hardware mode. Moreover, it must be ensured that, that the remote attestation works properly with that *enclave*.

To verify these, run *Intel-SGX-SDK*'s inbuilt attestated-TLS related examples in the newly set environment. Detailed steps regarding how to run those, can be found [here](https://github.com/intel/linux-sgx/tree/main/SampleCode/SampleAttestedTLS).


## 3. How to run $ROT$?
First download the source code of $ROT$ and go to the required directory by issuing the following command:
```
git clone https://github.com/sumitkumarpaul/data_rotting.git
cd data_rotting/Implementation/data-rotting/
```
Now we have to compile and run individual parties of $ROT$. To do so, a set of commands are required to be issued in multiple terminals. Following are the details. It assumes that *Intel-SGX-SDK* is installed in the following path: */opt/intel/sgxsdk/*. If it is installed in some other path, then modify the issued commands accordingly.

### 3.1 Prepare $Lib_{Enc}$

First compile a sample *enclave* and store that in $Lib_{Enc}$. To do so, open a new terminal *(Call it T1)* and issue the following commands:

```
source /opt/intel/sgxsdk/environment
cd libenc/enclave_collections/srcs
./update_libenc.sh 2
cd ../../../
```
Then follow the on screen instruction. Namely, locate the hexadecimal string in the ./tmp.dump file specifying MRENCLAVE value. Then copy that to the index 2 location of the global arrary *g_enc_details[]*, specified in *../../src/libenc_enc_info.h* file.

```
:
enc_details g_enc_details[] = {
    {
        0,
        :
    },
    :
    {
        2,
        :
        "0x81 0xd7 0x87 0xe1 0x33 0x3a 0xd9 0x21 0x12 0xea 0x80 0x70 0x92 0xf9 0x02 0xbc \n\
0xa7 0xf7 0x2a 0xb1 0x82 0xce 0xf6 0x14 0x0d 0x8a 0x7b 0x9e 0x9e 0x83 0x57 0x5e \n",/* Do not indent this line */
        :
    }
};
```
### 3.2 Compile and run $Lib_{Enc}$

Now, in $Lib_{Enc}$'s terminal, *(i.e., in T1)* and issue the following commands to compile and run $Lib_{Enc}$.

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

### 3.3 Compile and run Data-user in *usage approval* stage

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

### 3.4 Compile and run Data-owner

Open another new terminal *(Call it T3)* and issue the following commands:

```
cd data-owner;source /opt/intel/sgxsdk/environment;make clean;make; cd -;echo -e \"y\n\" |data-owner/data-owner 127.0.0.1 1235 127.0.0.1 1234 2 materials/sample_do_cert.pem materials/sample_do_enc_sign_pri_key.pem test/test_data_creater/data_cert_discrete/sample_do_data_20_attr.pem 1
```

The following should be the outputs:
```
rm -f data-owner ./src/data-owner-main.o ./src/do_tls_verify_callback.o ./src/do_tls_client.o ./src/do_initial_approval.o ./src/do_common.o ./src/do_tls_err_msg.o ./src/do_data_provision.o ./src/do_debug.o ./src/data-owner-main.d ./src/do_tls_verify_callback.d ./src/do_tls_client.d ./src/do_initial_approval.d ./src/do_common.d ./src/do_tls_err_msg.d ./src/do_data_provision.d ./src/do_debug.d
rm -f ./materials/enc.*
g++ -c -DCLIENT_USE_QVL -m64 -fPIC -Wno-attributes -I. -I/opt/intel/sgxsdk/include -I/usr/include/openssl  -DDEBUG -UNDEBUG -UEDEBUG -std=c++11 -DLOG_LEVEL=DEBUG_LEVEL_ERROR ./src/data-owner-main.c ./src/do_tls_verify_callback.cpp ./src/do_tls_client.cpp ./src/do_initial_approval.c ./src/do_common.c ./src/do_tls_err_msg.cpp ./src/do_data_provision.c ./src/do_debug.c
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



DO: [22-04-2024 16:18:52.610949] Approval-stage start
Succeed.
DO: [22-04-2024 16:18:52.705279] Successfully completed initial approval stage with data-user
DO: [22-04-2024 16:18:54.705376] Starting data-provision stage for the file: test/test_data_creater/data_cert_discrete/sample_do_data_20_attr.pem
Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'
DO: [22-04-2024 16:18:54.867662] Successfully completed data-provision stage

```
Do not worry about, if the following error is shown: 
`Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'`

In the meantime, something like the following should be shown in the data_user's terminal *(i.e., in T2)*:

```
:
Succeed.
[ENC.] [22-04-2024 16:18:54.898937] Fetched current block number during data provisioning is: 19712085
[ENC.] [22-04-2024 16:18:54.899033] Calculated expiry block number is: 19712090
```

### 3.5 Run Data-user in *Data Usage* stage

Go back to the data_user's terminal *(i.e., in T2)* and issue the following commands:

```
data-user/data-user access-data 127.0.0.1 1240
```

The following should be shown:


```
:
[ENC.] [22-04-2024 16:19:23.917498] Data is still not expired. Expiry block number is: (19712090) and the current block number is: (19712087)
[ENC.] [22-04-2024 16:19:23.917639] Start-data access
DU: [22-04-2024 16:19:23.918306] Data-user: Stop accessing the sealed-data
DU: [22-04-2024 16:19:23.918320] Data accessed successfully, the result of evaluation is: 20, return from enclave is = 0
```

Then wait for more than 1 minute and issue the same command again:

```
data-user/data-user access-data 127.0.0.1 1240
```

Something like the following should be shown:

```
data-user/data-user access-data 127.0.0.1 1240
[ENC.] [22-04-2024 16:21:35.641935] Data expired...!! Expiry block number (19712090) is smaller than the current block number (19712098)
[ENC.] [22-04-2024 16:21:35.642212] User provided personal data has expired
[ENC.] [22-04-2024 16:21:35.642294] Problem during opening the data-expiry date related file
[ENC.] [22-04-2024 16:21:35.642320] Cannot access the private data-file of the data-owner
DU: [22-04-2024 16:21:35.642784] Data-user: Stop accessing the sealed-data
DU: [22-04-2024 16:21:35.642797] Data accessed successfully, the result of evaluation is: -1, return from enclave is = 0
```

### 3.6 Clean everything

Go to the $Lib_{Enc}$'s terminal *(i.e., in T1)* and close that (by using ^c command).

To clean all the created materials, issue the following commands in the root directory:

```
cd libenc/; make clean; cd -;cd data-owner/; make clean; cd -;cd data-user ;make clean ENC_SRC_NAME=enclave_2_src; cd -
```