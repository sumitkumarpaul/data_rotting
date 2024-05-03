# Adjust the port numbers
# Run this one in one terminal before starting test (maybe in different phase)



#cap_ports="\'9001 or 9002 or 9003\'"
cap_ports="9001 or 9002 or 9003"

# Start capturing number of bytes: Input 1: The listening port
Start_net_bytes_cap() {
  echo -e "$cap_ports"

  sudo tcpdump -q -i lo port $cap_ports -w "captured_packets.pcap" -U > /dev/null 2>&1&

  local L_TCPDUMP_PID="$!"

  echo "$L_TCPDUMP_PID"

  return $L_TCPDUMP_PID
}

# Stop capturing number of bytes: Input 1: The listening port, Input 2: The PID of already running tcpdump
Stop_net_bytes_cap() {
  local TCPDUMP_PID=$1
  prev_num_bytes=0
  local num_bytes=1 # Initially changed this way to go enter into the loop
   
  while [ $num_bytes -gt $prev_num_bytes ]
  do
    sleep 10 # Sleep for some time
    du_op=$(du -b "captured_packets.pcap")
    prev_num_bytes=$num_bytes
    #cmd_op=$(echo "$du_op" | grep -oE '[0-9]+')
    num_bytes=$(echo "$du_op" | awk '{print $1}')
  done

  # No more packets are captured, so kill the tcpdump process
  echo "$num_bytes"
  rm -rf ./captured_packets.pcap
  sudo kill -SIGTERM $TCPDUMP_PID

  return $num_bytes
}

monitor_data_consume() {
  TCPDUMP_PID=$(Start_net_bytes_cap)
  
  cd data_user/
  ./run_data_user_client.sh 127.0.0.1 $1 "../data_owner/$1.enc"
  cd -

  # Calculate the number of bytes transferred
  num_bytes=$(Stop_net_bytes_cap $TCPDUMP_PID)

  echo "Captured bytes during data consumption: $num_bytes"
}

monitor_data_consume $1