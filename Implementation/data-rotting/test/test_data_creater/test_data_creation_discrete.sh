#!/bin/bash

data_conf_folder="./data_conf_discrete"
data_cert_folder="./data_cert_discrete"
org_base_conf_file="sample_do_pri_data_base.conf"
base_conf_file="tmp_sample_do_pri_data_base.conf"
csr_file="sample_do_pri_data.csr"
di_cert_file="sample_di_cert.pem"
pri_key_file="sample_di_pri_key.pem"

# Delete previous data
rm -rf $data_conf_folder
rm -rf $data_cert_folder

mkdir -p $data_conf_folder
mkdir -p $data_cert_folder

cp $org_base_conf_file $base_conf_file
for i in 20 40 60 80 100
do
    data_conf="$data_conf_folder/sample_do_data_"$i"_attr.conf"
    data_cert="$data_cert_folder/sample_do_data_"$i"_attr.pem"

    cp $base_conf_file $data_conf
    #echo "0.0.$i=ASN1:UTF8String:ATTR=01234567890123456789" >> $data_conf
    #echo "0.0.$i=ASN1:UTF8String:$RANDOM" >> $data_conf
    echo  "0.0.$i=ASN1:UTF8String:$i" >> $data_conf
    openssl x509 -req -days 3650 -in $csr_file -CA $di_cert_file -CAkey $pri_key_file -out $data_cert -extensions v3_req -extfile $data_conf -set_serial 01
    #openssl verify -verbose -CAfile $di_cert_file  $data_cert
    #openssl x509 -inform pem -noout -text -in $data_cert
    cp $data_conf $base_conf_file
done

exit

