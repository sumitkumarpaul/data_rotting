#!/bin/bash

# Initially ensure that the libenc and the enclave mrenclave values are same
#source /opt/intel/sgxsdk/environment
#Goto: libenc/enclave_collections/srcs/ 
#Run: update_libenc.sh 2


# Open terminal 1 and Start time-server
#gnome-terminal --tab -- bash -c "cd time-server;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;time-server/time-server 127.0.0.1 1240 2>./test.log; echo \"Press any key to exit\"; read;cd time-server;make clean;reset; cd -"
cd time-server;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;time-server/time-server 127.0.0.1 1240 2>./test.log; echo \"Press any key to exit\"; read;

# Open terminal 2 and Start LibEnc
#gnome-terminal --tab -- bash -c "cd libenc;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;libenc/libenc 127.0.0.1 1234 2>>./test.log; echo \"Press any key to exit\"; read; cd libenc/; make clean;reset; cd -"
cd libenc;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;libenc/libenc 127.0.0.1 1234 2>>./test.log; echo \"Press any key to exit\"; read;

# Open terminal 3 and Start Data-User in get-approval mode
#gnome-terminal --tab -- bash -c "cd data-user;source /opt/intel/sgxsdk/environment;make clean ENC_SRC_NAME=enclave_2_src;make ENC_SRC_NAME=enclave_2_src;reset;  cd -;data-user/data-user get-approval 127.0.0.1 1235 127.0.0.1 1234 127.0.0.1 1236 2>> ./test.log;sleep 2;data-user/data-user access-data 127.0.0.1 1240 2>>./test.log; sleep 1; echo \"0 \" | nc 127.0.0.1 1240; echo \"Press any key to exit\"; read; cd data_user/;make clean ENC_SRC_NAME=enclave_2_src;reset; cd -"
cd data-user;source /opt/intel/sgxsdk/environment;make clean ENC_SRC_NAME=enclave_2_src;make ENC_SRC_NAME=enclave_2_src;reset; cd -;data-user/data-user get-approval 127.0.0.1 1235 127.0.0.1 1234 127.0.0.1 1236 >> ./test.log 2>&1;sleep 2;

# Open terminal 4 and Start Data-Owner
#gnome-terminal --tab -- bash -c "cd data-owner;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;echo -e \"y\n\" |data-owner/data-owner 127.0.0.1 1235 127.0.0.1 1234 2 materials/sample_do_cert.pem materials/sample_do_enc_sign_pri_key.pem test/test_data_creater/data_cert/sample_do_data_10_attr.pem 2012422572 2>>./test.log; sleep 1; echo STOP | nc 127.0.0.1 1234; echo \"Press any key to exit\"; read; cd data_owner/; make clean;reset; cd -"
# For TSP related implementation cd data-owner;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;echo -e \"y\n\" |data-owner/data-owner 127.0.0.1 1235 127.0.0.1 1234 2 materials/sample_do_cert.pem materials/sample_do_enc_sign_pri_key.pem test/test_data_creater/data_cert/sample_do_data_10_attr.pem 2012422572 2>>./test.log; sleep 1; echo STOP | nc 127.0.0.1 1234; echo \"Press any key to exit\"; read; cd data-owner/; make clean;reset; cd -;
cd data-owner;source /opt/intel/sgxsdk/environment;make clean;make;reset; cd -;echo -e \"y\n\" |data-owner/data-owner 127.0.0.1 1235 127.0.0.1 1234 2 materials/sample_do_cert.pem materials/sample_do_enc_sign_pri_key.pem test/test_data_creater/data_cert_discrete/sample_do_data_20_attr.pem 1 2>>./test.log; sleep 1; echo STOP | nc 127.0.0.1 1234; echo \"Press any key to exit\"; read;

# Goto terminal 3 again and Start Data-User in access-data mode
data-user/data-user access-data 127.0.0.1 1240 >>./test.log 2>&1; sleep 1; echo \"0 \" | nc 127.0.0.1 1240; echo \"Press any key to exit\"; read;

# Clean everything
cd time-server;make clean;reset; cd -;
cd libenc/; make clean;reset; cd -;
cd data-owner/; make clean;reset; cd -;
cd data-user ;make clean ENC_SRC_NAME=enclave_2_src;reset; cd -


