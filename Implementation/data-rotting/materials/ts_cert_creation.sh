# Create the private key of timestamp CA server
openssl genrsa -out "sample_ts_root_ca_pri_key.pem" 3072

# Create the self-signed timestamp CA certificate
openssl req -x509 -sha256 -new -nodes -key "sample_ts_root_ca_pri_key.pem" -days 3650 -subj '/CN=Sample root CA for timestamping server' -out "sample_ts_root_ca_cert.pem"

# Create the private key of timestamp server
openssl genrsa -out sample_ts_pri_key.pem 3072

# Create CSR for the trusted time server
openssl req -new -key "sample_ts_pri_key.pem" -out "sample_ts_pri.csr" -sha256 -subj '/CN=Sample trusted time-stamping server'

# Create a self-signed timestamping server certificate
openssl x509 -req -days 3650 -in "sample_ts_pri.csr" -CA "sample_ts_root_ca_cert.pem" -CAkey "sample_ts_root_ca_pri_key.pem" -sha256 -set_serial 01 -out "sample_ts_cert.pem" -extfile "sample_ts.cnf" -extensions v3_tsa
#openssl x509 -req -days 730 -in tsa.csr -CA tsaroot.crt -CAkey tsaroot.key -set_serial 01 -out tsa.crt -extfile extKey.cnf

openssl x509 -in "sample_ts_cert.pem" -text

# Convert certificates to DER format
openssl x509 -in sample_ts_root_ca_cert.pem -out sample_ts_root_ca_cert.der -outform DER 
openssl x509 -in sample_ts_cert.pem -out sample_ts_cert.der -outform DER 

openssl x509 -in sample_ts_root_ca_cert.pem -out sample_ts_root_ca_cert.c -C 
openssl x509 -in sample_ts_cert.pem -out sample_ts_cert.c -C 
