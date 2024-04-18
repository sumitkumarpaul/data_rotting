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

ENC_SRC_PATH := ../$(ENC_SRC_NAME)
AUTOGEN_U_SRC_PATH := ../autogen_src
DU_LOG_LEVEL := DEBUG_LEVEL_ERROR
DU_C_Flags := -O2 -fPIC -Wno-attributes -IInclude -I$(SGX_SDK)/include -std=c++11 -DENC_LOG_LEVEL=$(SGX_LOG_LEVEL) 

include $(ENC_SRC_PATH)/sgxenv.mk

INCDIR := $(SGX_SDK)/include
SOCKET_INCDIR := $(SOCKET_DIR)/include

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	 $(SGX_EDGER8R) $(ENC_SRC_PATH)/enclave/entire_enc.edl --untrusted \
		--untrusted-dir $(AUTOGEN_U_SRC_PATH) \
    	--search-path $(INCDIR) \
		--search-path $(ENC_SRC_PATH)/common \
		--search-path $(SOCKET_INCDIR) \
		--search-path $(SGXSSL_PKG_PATH)/Linux/package/include \
		--search-path $(SGXSSL_PKG_PATH)/include
	
	$(CC) -c $(App_C_Flags) $(AUTOGEN_U_SRC_PATH)/entire_enc_u.c
	$(CC) -c $(App_C_Flags) -DLOG_LEVEL=$(DU_LOG_LEVEL) data-user-main.c du_debug.c du_enc_mang.c
	$(CXX) -c -DM_TLS_SERVER $(App_Cpp_Flags) $(ENC_SRC_PATH)/sgx_socket/untrusted_sgx_socket.cpp $(ENC_SRC_PATH)/common/ucommon.cpp
	$(CXX) -o data-user untrusted_sgx_socket.o entire_enc_u.o ucommon.o data-user-main.o du_debug.o du_enc_mang.o $(App_Link_Flags)
	cp data-user ../

clean:
	rm -f data-user *.o
	rm -f ../data-user *.o
	rm -rf $(AUTOGEN_U_SRC_PATH)
