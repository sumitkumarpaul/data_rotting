.PHONY: all build clean

ENC_SRC_NAME ?=enclave_2_src

all: build 

build:
	@echo "Building solution with: $(ENC_SRC_NAME)"
	$(MAKE) -C data-owner
	$(MAKE) $(if $(ENC_SRC_NAME),ENC_SRC_NAME=$(ENC_SRC_NAME)) -C data-user
	$(MAKE) -C libenc
	$(MAKE) -C time-server

clean:
	$(MAKE) -C data-owner clean
	$(MAKE) $(if $(ENC_SRC_NAME),ENC_SRC_NAME=$(ENC_SRC_NAME)) -C data-user clean
	$(MAKE) -C libenc clean
	$(MAKE) -C time-server clean
