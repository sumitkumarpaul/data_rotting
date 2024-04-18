
echo -e "Please make sure to run the following command in this terminal, otherwise it will not work:\nsource /opt/intel/sgxsdk/environment"
read

echo "This script will re-compile the code of the enclave for your system and will copy the compiled enclave to data-user's code base"

if test "$#" -ne 1; then
    echo "Please enter the id of the enclave, which you want to update:"
    read enc_id
else
    enc_id=$1
fi

echo "Updating libenc with the updated information of enclave: $enc_id"

LIBENC_SRC_FOLDER="../.."
ENC_SRC_FOLDER="enclave_"$enc_id"_src"
ENC_SRC_OP_FOLDER="enclave_"$enc_id"_src/enclave"
ENC_DST_FOLDER="../enclaves"
EDL_DST_FOLDER="../edls"
CONFIG_DST_FOLDER="../configs"

# Create enclave destination folder, if not already present
if [ ! -d $ENC_DST_FOLDER ]; then
  mkdir -p $ENC_DST_FOLDER;
fi

rm -rf "../../../data-user/src/"$ENC_SRC_FOLDER 
cp -r  $ENC_SRC_FOLDER "../../../data-user/src/"$ENC_SRC_FOLDER 

make -C $ENC_SRC_FOLDER clean
make -C $ENC_SRC_FOLDER

cp $ENC_SRC_OP_FOLDER"/enclave.so" $ENC_DST_FOLDER"/enclave_"$enc_id".so"
cp $ENC_SRC_OP_FOLDER"/entire_enc.edl" $EDL_DST_FOLDER"/enclave_"$enc_id".edl"
cp $ENC_SRC_OP_FOLDER"/enclave.config.xml" $CONFIG_DST_FOLDER"/enclave_"$enc_id".config.xml"

sgx_sign dump -enclave "enclave_"$enc_id"_src/enclave/enclave.signed.so" -dumpfile "tmp.dump"

echo "Please update the MRENCLAVE information in g_enc_details[] within file: "$LIBENC_SRC_FOLDER/src/"libenc_enc_info.h according to the content of ./tmp.dump"

echo -e "\n\n\n\n"
read  -n 1 -p "Please enter a key after complete doing this"

make clean -C $ENC_SRC_FOLDER

zip -r $ENC_SRC_FOLDER".zip" $ENC_SRC_FOLDER

make -C $LIBENC_SRC_FOLDER clean
make -C $LIBENC_SRC_FOLDER

rm ./tmp.dump

