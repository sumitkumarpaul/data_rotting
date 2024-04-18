# Compile the source code first and generate the required binaries
cd ./u_data_user/;make -s clean;make -s;cd ..
cd ./u_data_owner/;make -s clean;make -s;cd ..

for i in 1 10 100 1000 10000
do
    sudo killall u_data_user > /dev/null 2>&1
    rm -rf "./non_priv_log_"$i".txt"
    echo "Testing non_priv for: "$i" data items"

    # Start tcpdump
    sudo tcpdump -q -i lo dst port 1235 or src port 1235 -w captured_packets.pcap -U > /dev/null 2>&1&
 
    # Start data-user
    cd ./u_data_user/; ./u_data_user "1235" "../test_data_creater/certs/server-cert.pem" "../test_data_creater/certs/server-key.pem" >> "../non_priv_log_"$i".txt"&disown;cd ../

    # Start data-owner
    cd ./u_data_owner;sleep 2;./u_data_owner 127.0.0.1 1235 "../test_data_creater/data_cert/sample_do_data_"$i"_attr.pem" 2308185037 >> "../non_priv_log_"$i".txt"&disown;cd ../

    # Calculate the number of bytes transferred
    prev_num_bytes=0
    num_bytes=1 # Initially changed this way to go enter into the loop
   
    while [ $num_bytes -gt $prev_num_bytes ]
    do
        sleep 10 # Sleep for some time
        du_op=$(du -b captured_packets.pcap)
        prev_num_bytes=$num_bytes
        cmd_op=$(echo "$du_op" | grep -oE '[0-9]+')
        num_bytes=$((cmd_op))
    done

    # No more packets are captured, so kill the tcpdump process
    sudo killall -SIGTERM tcpdump
    rm -rf captured_packets.pcap
    echo -e "\nTotal number of transferred bytes: $num_bytes" >> "./non_priv_log_"$i".txt"

done


# Clean the source code
cd ./u_data_user/;make -s clean;cd ..
cd ./u_data_owner/;make -s clean;cd ..