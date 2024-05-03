.PHONY: all build clean

ENC_FOLDER_NAME := enclave_1_src

all: build 

build:
	$(MAKE) -C host

clean:
	$(MAKE) -C host clean

build_enc:
	$(MAKE) -C $(ENC_FOLDER_NAME)

clean_enc:
	$(MAKE) -C $(ENC_FOLDER_NAME) clean
