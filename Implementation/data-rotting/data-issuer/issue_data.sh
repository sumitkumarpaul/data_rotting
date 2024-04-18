#!/bin/bash

if test "$#" -ne 2; then
    echo "Please enter the data-request file(*csr):"
    read data_csr
    echo "Please enter the data-details(*conf):"
    read data_conf
else
    data_csr=$1
    data_conf=$2
fi

# Create a new private data-certificate for the data-owner, signed by the data-issuer
#openssl x509 -req -in $data_csr -CA sample_di_cert.pem -CAkey sample_di_pri_key.pem -CAcreateserial -out sample_do_pri_data_cert.pem -extensions v3_req -extfile $data_conf -set_serial 01
openssl x509 -req -days 3650 -in $data_csr -CA sample_di_cert.pem -CAkey sample_di_pri_key.pem -out sample_do_pri_data_cert.pem -extensions v3_req -extfile $data_conf -set_serial 01

# Show the details of the data-owner's private data-certificate
openssl x509 -inform pem -noout -text -in 'sample_do_pri_data_cert.pem'

# Verify the newly generated data-owner's private data certificate with the data-issuer certificate
openssl verify -verbose -CAfile sample_di_cert.pem  sample_do_pri_data_cert.pem
