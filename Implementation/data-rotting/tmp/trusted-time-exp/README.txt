---------------------------------------------------------------
  Purpose: How to compile and deploy the "data-user" software
---------------------------------------------------------------
TODO

Introduction:
	- This is actually a non-enclave software which is responsible for preparing the 
	  environment for later stage. However, this software launches an enclave, so SGX-enabled
	  system is required. This software can be run in three(??) different modes:
		- get-approval: In this mode, "data-user" gets approval from "data-owner".
						At the end of this mode, "data-user" receives two files
							1. The signed-enclave file, which will be perform operation on data-owner's data
							2. The edl file, after getting this file "data-owner" need to develop
						   	   (or if already developed then only link) the expected OCALLs by the enclave.
							   - Ideally, all the required OCALLs should be pre-developed in "data-user" side
						At the end, "data-owner" will launch the enclave and notify the "data-owner" to connect
						with the newly launched enclave via some specific port

Requirements:
	- Linux system
		- We have developed with: TODO
	- SGX with FLC is REQUIRED
	- Inetl SGX-SDK for Linux should be installed
		- Installation guide: https://github.com/intel/linux-sgx
			- We have developed and tested with: Linux 2.18 Open Source Gold Release 
	- If external clients are expected then:
		- Ensure internet reachability
		- Make sure firewall is not blocking the listening port
	- SGX2-capability not required

How to compile:
	- Go to the directory, where this README file is present
    - Copy the unzipped version of the source folder of the enclave with in src/, which is going to be executed
    - Change the macro ENC_FOLDER_NAME with that value in the Makefile in this level
    - Example:
        -- Assume the enclave_x will be used by data-user and corresponding zipped source code obtained from libenc is: enclave_x_src.zip
        -- Unzip enclave_x_src.zip, it should produce enclave_x_src/ put it within src/
        -- Following will be the folder structure now
            data-user
            |
            `-- Makefile
             |- README.txt
             |- src
                |
                `-- Makefile
                 |- host
                 `- enclave_x_src

        -- Set the ENC_FOLDER_NAME := src/enclave_0_src in the top Makefile
	- Run: "ENC_SRC_NAME=enclave_x_src" to compile with enclave_x
	- Run: "make ENC_SRC_NAME=enclave_x_src clean" to clean
	- After successful compilation, the binary executable "data-user" will be generated in the folder

How to run:
	- Run: ./data-user <mode> <IP address> <port>
	- After receiving the edl file from LibEnc:
		- The required

