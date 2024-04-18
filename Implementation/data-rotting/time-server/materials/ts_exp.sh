# Create time stamping request
echo -e "\n\nCreating time stamping request"
echo -e "===================================\n"
openssl ts -query -config sample_ts_signer_conf.cnf -data design1.txt -out design1.tsq

# Show the details of the time stamp request
echo -e "\n\nShowing the details of the time stamp request"
echo -e "=============================================\n"
 openssl ts -query -config sample_ts_signer_conf.cnf -in design1.tsq -text

# Generate a time stamp response with the time stamp server's private key
echo -e "\n\nGenerating a time stamp response with the time stamp server's private key"
echo -e "=============================================================================\n"
openssl ts -reply -config sample_ts_signer_conf.cnf -queryfile design1.tsq -inkey sample_ts_pri_key.pem -signer sample_ts_cert.pem -out design1.tsr
#openssl ts -reply -queryfile design1.tsq -inkey sample_ts_pri_key.pem -signer sample_ts_cert.pem -out design1.tsr

# Show the details of the time stamp response
echo -e "\n\nShow the details of the time stamp response"
echo -e "==========================================\n"
openssl ts -reply -config sample_ts_signer_conf.cnf -in design1.tsr -text

# Verify the time stamp response with the time stamp server's certificate
echo -e "\n\nVerify the time stamp response with the time stamp server's certificate"
echo -e "========================================================================\n"
#openssl ts -verify -queryfile design1.tsq -in design1.tsr -CAfile cacert.pem -untrusted tsacert.pem
openssl ts -verify -config sample_ts_signer_conf.cnf -queryfile design1.tsq -in design1.tsr -CAfile sample_ts_root_ca_cert.pem -untrusted sample_ts_cert.pem

# Show the details of the time stamp verification
