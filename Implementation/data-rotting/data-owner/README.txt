---------------------------------------------------------------
  Purpose: How to compile and deploy the "data-owner" software
---------------------------------------------------------------
Introduction:
	- This software which responsible for sending approval to the data-user and then
      send the actual data to the deployed enclave in the data-user side.

Requirements:
	- Linux system
		- We have developed with: TODO
	- Inetl SGX-SDK for Linux should be installed
		- Installation guide: https://github.com/intel/linux-sgx
			- We have developed and tested with: Linux 2.18 Open Source Gold Release
    - OpenSSL must be installed in the system
        - We have developed and tested with: OpenSSL 1.1.1f  31 Mar 2020
    - Ensure internet reachability with LibEnc and data-user
	- SGX-capability not required

How to compile:
	- Go to the directory, where this README file is present
	- Make sure SGX-SDK is installed and the environment variables are sourced
	- Run: "make" to compile
	- Run: "make clean" to clean
	- After successful compilation, the binary executable "data-owner" will be generated in this folder

How to create new certified data for testing:
    - Modify materials/private_data/sample_do_pri_data.conf according to the requirement
    - Execute the command: make data_req_create
    - Submit the newly generated file: materials/private_data/sample_do_pri_data.conf for obtaining  a new
      certified data file from the data-issuer
      
Data-owner's certificate:
	- This certificate, private and public keys are used for signing the enclave's content
	- Command for creating a new signing certificate: make cert_create
	- Command for deleting existing signing certificate: make cert_del
      
How to run:
     - Run: ./data-owner <du-ip> <du-port> <libenc-ip> <libenc-port> <srv-req-id> <do-cert> <do-pri-key> <do-pri-data-file> <exp-tim>
      Inputs:
      - du-ip           : IP-address of data-user
      - du-port         : Listening port of data-user
      - libenc-ip       : IP-address of libenc
      - libenc-port     : Listening port of libenc
      - srv-req-id      : ID of the requesting service's ID from data-user(service provider)
      - do-cert         : Certificate file of data-owner
      - do-pri-key      : Private key file of data-owner
      - do-pri-data-file: This file contains the required data in the specified format
      - exp-tim         : Expiry time in terms of epoch seconds
      
How to test with sample values:
	- Run: make test
		- By default it executes: ./data-owner 127.0.0.2 1235 127.0.0.1  1234 1 ./materials/sample_do_cert.pem ./materials/sample_do_pri_key.pem ./materials/private_data/sample_do_pri_data_cert.pem 1737332245
   

