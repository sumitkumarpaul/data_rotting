----------------------------------------------
Purpose: Overview of this framework
----------------------------------------------
Introduction:
	- This folder contains all the materials required for this application
	- It contains four sub-directories:
		- libenc
		- data-owner
		- data-user
		- data-issuer(Only for testing purpose)
	- Each have different purpose and ideally deployed in different systems
	- For details of each parts please refer to the README of each individual sub-folders

Order of deployment:
	- At first LibEnc must be deployed/executed
	- Then DataUser should be deployed/executed
	- Finally DataUser program must be deployed/executed
		- Before execution of the data-user, it should obtain certified data from data-issuer

Caution:
	- Make sure each part is reachable by others

TODO:
    - DO and DU's certificate verification is not yet present in the code
    - Change implememtation according to Figure 3
    - Check the expected MRENCLAVE value in the report during the Attested TLS channel establishment
        - Might be useful: oe_verify_evidence
    - TODO sign enclave 2, but deploy enclave 3
    - From command line argument, the IP address and port of data-user should be mentioned 
    - Complete the implementation of the enclave 1
    - Change print so that it is easily exportable to csv and also, during problem it should print the error location
    - Change the level of all the print statement
    - Review the code
    - File name and, which function will be part of which file
    - There are several compilation wraning, fix them. Some of them are self impsed as reminder
    - Error path checking and memory leaking, BIO_free() or BIO_free_all()?

