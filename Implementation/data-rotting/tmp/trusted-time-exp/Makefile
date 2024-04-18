.PHONY: all build clean

ENC_FOLDER_NAME := src/$(ENC_SRC_NAME)
CERT_DIR ?= ./materials

all: build 

build:
	mkdir -p materials
	$(MAKE) -C src
	mv src/host/data-user .

clean:
	$(MAKE) -C src clean
	rm -rf data-user

build_enc:
	$(MAKE) -C $(ENC_FOLDER_NAME)

clean_enc:
	$(MAKE) -C $(ENC_FOLDER_NAME) clean

.PHONY: cert_create
cert_create:
	@echo "It will a new certificate, private and public key in the "$(CERT_DIR)" directory, if it is not already present"
	# generate a private key with the correct length
	openssl genrsa -out $(CERT_DIR)/sample_du_pri_key.pem -3 3072
	sudo chmod +r $(CERT_DIR)/sample_du_pri_key.pem
	
	# generate corresponding public key
	openssl rsa -in $(CERT_DIR)/sample_du_pri_key.pem -pubout -out $(CERT_DIR)/sample_du_pub_key.pem
	
	# Create a self-signed certificate
	openssl req -new -x509 -key $(CERT_DIR)/sample_du_pri_key.pem -out $(CERT_DIR)/sample_du_cert.pem -days 3600 -subj "/C=XY/ST=Some state/L=Some location/O=Some organization/CN=Data-User 1"


.PHONY: cert_del
cert_del:
	@echo "It will delete the certificates from "$(CERT_DIR)" directory"
	$(RM) $(CERT_DIR)/sample_du*
