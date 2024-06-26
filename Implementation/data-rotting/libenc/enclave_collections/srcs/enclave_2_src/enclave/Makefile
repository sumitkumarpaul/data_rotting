#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include ../sgxenv.mk

ENC_NAME := enclave
INCDIR := $(SGX_SDK)/include
ENC_FILE_Name := $(ENC_NAME).so
Signed_ENC_FILE_Name := $(ENC_NAME).signed.so
Enclave_Test_Key := private_test_key.pem

.PHONY: all build clean run

# Add all the source files here
SRC_FILES = enclave_func.cpp ../common/tls_server.cpp ../sgx_socket/htons.c ../sgx_socket/htonl.c ../sgx_socket/trusted_sgx_socket.cpp ../common/utility.cpp ../common/openssl_utility.cpp ../common/tcommon.cpp ../common/err_msg.cpp ../common/tls_verify_callback.cpp ../common/data_provision.cpp ../common/data_access.cpp

OBJ_FILES = enclave_func.o entire_enc_t.o trusted_sgx_socket.o htonl.o htons.o tls_server.o utility.o openssl_utility.o tcommon.o err_msg.o data_provision.o tls_verify_callback.o data_access.o

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(SGX_EDGER8R) ./entire_enc.edl --trusted \
		--search-path . \
		--search-path $(INCDIR) \
		--search-path $(SOCKET_DIR)/include \
		--search-path ../common \
		--search-path $(SGXSSL_PKG_PATH)/include

	$(CXX) -c -DM_TLS_SERVER $(Enclave_Cpp_Flags) -I. -std=c++11 -include "tsgxsslio.h" ${SRC_FILES}
	$(CC) -c $(Enclave_C_Flags) -I. entire_enc_t.c
	$(CXX) -o $(ENC_FILE_Name) $(OBJ_FILES) $(Enclave_Link_Flags)  

sign:
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "There is no enclave test key<Enclave_private_test.pem>."
	@echo "The project will generate a key<Enclave_private_test.pem> for test."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(ENC_FILE_Name) \
		-out $(Signed_ENC_FILE_Name) -config enclave.config.xml

clean:
	rm -f *.o $(ENC_FILE_Name) $(Signed_ENC_FILE_Name) entire_enc_t.*
