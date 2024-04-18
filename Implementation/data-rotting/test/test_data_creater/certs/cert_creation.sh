
openssl genrsa -out ca-key.pem -3 3072

chmod 400 ca-key.pem

openssl req -new -x509 -nodes -days 365000 -key ca-key.pem -out ca-cert.pem

openssl req -newkey rsa:3072 -nodes -days 365000 -keyout server-key.pem -out server-req.pem

openssl x509 -req -days 365000 -set_serial 01 -in server-req.pem -out server-cert.pem -CA ca-cert.pem  -CAkey ca-key.pem

openssl req -newkey rsa:3072 -nodes -days 365000 -keyout client-key.pem -out client-req.pem

openssl x509 -req -days 365000 -set_serial 01 -in client-req.pem -out client-cert.pem -CA ca-cert.pem -CAkey ca-key.pem

openssl verify -CAfile ca-cert.pem ca-cert.pem server-cert.pem

openssl verify -CAfile ca-cert.pem ca-cert.pem client-cert.pem

