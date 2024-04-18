# Each data item is of 32bit, which means the representation in decimal will be of: 10 digits 
# FE expands 32bit to 2048bit, which is a 617 digit number 

for i in 1 10 100 1000 10000
do
    rm -rf "./FE_Dummy_input_$i.txt"
    for ((j=1; j<=$i; j++))
    do
        random_di=$(cat /dev/urandom | tr -dc 0-9 | head -c "$(shuf -i 617-617 -n 1)")
        echo -e "$random_di" >> "./FE_Dummy_input_$i.txt"
    done
done