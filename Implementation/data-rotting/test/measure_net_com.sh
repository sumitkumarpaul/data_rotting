# Adjust local port number and blockchain information
# This same script must be executed with some minor modification to determine the number of network transferred bytes
# During data access phase, local port must not be listened
# Start this script in a seperate terminal before starting DU

cap_ports_local="1236"
bc_ip="mainnet.infura.io"

# Start capturing number of bytes: Input 1: The listening port
Start_net_bytes_cap() {
  echo -e "$cap_ports_local"

  #sudo tcpdump -q -i lo port $cap_ports_local -w "captured_packets.pcap" -U > /dev/null 2>&1&

  sudo tcpdump -q -i any host $bc_ip -w "captured_packets_bc.pcap" -U > /dev/null 2>&1&

  local L_TCPDUMP_PID="$!"

  echo "$L_TCPDUMP_PID"

  return $L_TCPDUMP_PID
}

# Stop capturing number of bytes: Input 1: The listening port, Input 2: The PID of already running tcpdump
Stop_net_bytes_cap() {
  local TCPDUMP_PID=$1
  prev_num_bytes=0
  local num_bytes=1 # Initially changed this way to go enter into the loop
   
  #while [ $num_bytes -gt $prev_num_bytes ]
  #do
  #  sleep 10 # Sleep for some time
  #  du_op=$(du -b "captured_packets.pcap")
  #  prev_num_bytes=$num_bytes
  #  #cmd_op=$(echo "$du_op" | grep -oE '[0-9]+')
  #  num_bytes=$(echo "$du_op" | awk '{print $1}')
  #done

  # No more packets are captured, so kill the tcpdump process
  echo "Bytes transferred for data transfer: $num_bytes"

  prev_num_bytes=0
  local num_bytes=1 # Initially changed this way to go enter into the loop
   
  while [ $num_bytes -gt $prev_num_bytes ]
  do
    sleep 10 # Sleep for some time
    du_op=$(du -b "captured_packets_bc.pcap")
    prev_num_bytes=$num_bytes
    #cmd_op=$(echo "$du_op" | grep -oE '[0-9]+')
    num_bytes=$(echo "$du_op" | awk '{print $1}')
  done
  echo "Bytes transferred for BC access: $num_bytes"
  sudo kill -SIGTERM $TCPDUMP_PID
  #rm -rf ./captured_packets.pcap
  rm -rf ./captured_packets_bc.pcap

  return $num_bytes
}

monitor_data_transfer() {
  TCPDUMP_PID=$(Start_net_bytes_cap)
  
  data-user/data-user get-approval 127.0.0.1 1235 127.0.0.1 1234 127.0.0.1 1236 &

  # Calculate the number of bytes transferred
  num_bytes=$(Stop_net_bytes_cap $TCPDUMP_PID)

  echo "Captured bytes: $num_bytes"
}

monitor_data_transfer $1