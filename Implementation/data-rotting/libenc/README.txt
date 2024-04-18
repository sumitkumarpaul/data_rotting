----------------------------------------------
Purpose: How to compile and deploy the LibEnc
----------------------------------------------
Introduction:
	- This is a trusted library maintained in some publicly accible location.
	  Anyone can see its contents and verify it.
	- It is a server program, it accepts one request at a time from a client
      then process and reply it and then tears off the connection with the client.

Requirements:
	- Linux system
	- Standard systems like gcc, make installed
	- If external clients are expected then:
		- Ensure internet reachability
		- Make sure firewall is not blocking the listening port
	- SGX-capability not required

How to compile:
	- Go to the directory, where this README file is present
	- Run: "make" to compile
	- Run: "make clean" to clean
	- After successful compilation, the binary executable "libenc" will be generated in this folder

How to add new enclaves in this library:
    - Curently, this libray is usable for demonstration purpose and it supports only two enclaves.
      However adding support of new enclave is not difficult.
      To add support for a new enclave, add corresponding configuration file, edl file, zipped source
      code and the unsigned enclave file in the following directory structure.
    
        -- enclave_collections
           |-- configs
           |   |-- enclave_0.config.xml
           |   `-- enclave_1.config.xml
           |-- edls
           |   |-- enclave_0.edl
           |   `-- enclave_1.edl
           |-- enclaves
           |   |-- enclave_0.so
           |   `-- enclave_1.so
           `-- srcs
               |-- enclave_0_src.zip
               `-- enclave_1_src.zip

    - Update the following header file accordingly:
    
        `-- src
            |-- libenc_enc_info.h
            `-- 

How to run:
	- Run: ./libenc <IP address> <port>
