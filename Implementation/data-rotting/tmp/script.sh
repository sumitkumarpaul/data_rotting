echo -e "Generating timestamping request:"
echo -e "================================\n"

openssl ts -query -data data.txt -out ts.req

openssl ts -query -in ts.req -text

echo -e "\n\nGetting time-stamping response from http://timestamp.digicert.com/:"
echo -e "=======================================================================\n"
curl -s -S --data-binary @ts.req http://timestamp.digicert.com/ -o ts.rsp -v
openssl ts -reply -in ts.rsp -text

echo -e "\n\nVerify the response:"
echo -e "=======================================================================\n"

