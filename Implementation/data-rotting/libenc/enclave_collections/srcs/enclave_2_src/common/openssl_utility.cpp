/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include "openssl_utility.h"
#include <sgx_tprotected_fs.h>
#include "common.h"

char g_enc_buffer[ENC_BUF_SZ];
char g_enc_buffer1[ENC_BUF_SZ];

sgx_status_t generate_certificate_and_pkey(X509*& certificate, EVP_PKEY*& pkey)
{
    quote3_error_t qresult = SGX_QL_SUCCESS;
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    uint8_t* output_certificate = NULL;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    const unsigned char* certificate_buffer_ptr = nullptr;
    BIO* mem = nullptr;
    int key_type = RSA_TYPE;

    if (key_type) {
        enc_print_log(ENC_DEBUG_LEVEL_INFO, " generating keys by EC P-384\n");
    }
    else
    {
        enc_print_log(ENC_DEBUG_LEVEL_INFO, " generating keys by RSA 3072\n");
    }
    result = generate_key_pair(
        key_type, &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);
    if (result != SGX_SUCCESS)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, " failed to generate RSA key pair\n");
        goto done;
    }

    enc_print_log(ENC_DEBUG_LEVEL_DUMP, "public_key_buf_size:[%ld]\n", public_key_buffer_size);
    enc_print_log(ENC_DEBUG_LEVEL_DUMP, "%s\n", public_key_buffer);
    enc_print_log(ENC_DEBUG_LEVEL_DUMP, "private_key_buf_size:[%ld]\n", private_key_buffer_size);
    enc_print_log(ENC_DEBUG_LEVEL_DUMP, "%s\n", private_key_buffer);

    qresult = tee_get_certificate_with_evidence(
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        &output_certificate,
        &output_certificate_size);

    if (qresult != SGX_QL_SUCCESS || output_certificate == nullptr)
    {
        if (output_certificate == nullptr)
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, " null certificate\n");
        p_sgx_tls_qe_err_msg(qresult);
        goto done;
    }

    // temporary buffer required as if d2i_x509 call is successful
    // certificate_buffer_ptr is incremented to the byte following the parsed
    // data. sending certificate_buffer_ptr as argument will keep
    // output_certificate pointer undisturbed.

    certificate_buffer_ptr = output_certificate;

    if ((certificate = d2i_X509(
             nullptr,
             &certificate_buffer_ptr,
             (long)output_certificate_size)) == nullptr)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed to convert DER format certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buffer, -1);
    if (!mem)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = SGX_SUCCESS;
done:
    if (private_key_buffer)
        free(private_key_buffer);
    if (public_key_buffer)
        free(public_key_buffer);
    certificate_buffer_ptr = nullptr;

    if (mem)
        BIO_free(mem);
    if (output_certificate)
        tee_free_certificate(output_certificate);
    return result;
}

sgx_status_t load_tls_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& certificate,
    EVP_PKEY*& pkey)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;

    if (generate_certificate_and_pkey(certificate, pkey) != SGX_SUCCESS)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot generate certificate and pkey\n");
        goto exit;
    }

    if (certificate == nullptr)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "null cert\n");
        goto exit;
    }

    if (!SSL_CTX_use_certificate(ctx, certificate))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot load certificate on the server\n");
        goto exit;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot load private key on the server\n");
        goto exit;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Private key does not match the public certificate\n");
        goto exit;
    }
    result = SGX_SUCCESS;
exit:
    return result;
}

sgx_status_t initalize_ssl_context(SSL_CONF_CTX*& ssl_conf_ctx, SSL_CTX*& ctx)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // Configure the SSL context based on Open Enclave's security guidance.
    const char* cipher_list_tlsv12_below =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-"
        "AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-"
        "AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384";
    const char* cipher_list_tlsv13 =
        "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
    const char* supported_curves = "P-521:P-384:P-256";

    SSL_CONF_CTX_set_ssl_ctx(ssl_conf_ctx, ctx);
    SSL_CONF_CTX_set_flags(
        ssl_conf_ctx,
        SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CLIENT);
    int ssl_conf_return_value = -1;
    
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MinProtocol", "TLSv1.2")) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
            "Setting MinProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MaxProtocol", "TLSv1.3")) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
            "Setting MaxProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "CipherString", cipher_list_tlsv12_below)) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
            "Setting CipherString for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "Ciphersuites", cipher_list_tlsv13)) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
            "Setting Ciphersuites for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "Curves", supported_curves)) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
            "Setting Curves for ssl context configuration failed with error %d "
            "\n",
            ssl_conf_return_value);
        goto exit;
    }
    if (!SSL_CONF_CTX_finish(ssl_conf_ctx))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error finishing ssl context configuration \n");
        goto exit;
    }
    ret = SGX_SUCCESS;
exit:
    return ret;
}

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int ret = -1;
    unsigned char buffer[200]; // the expected payload to be read from peer is
                               // at maximum of size 200
    int bytes_read = 0;
    do
    {
        unsigned int len = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        bytes_read = SSL_read(ssl_session, buffer, (size_t)len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        enc_print_log(ENC_DEBUG_LEVEL_ERROR, " %d bytes read from session peer\n", bytes_read);

        // check to see if received payload is expected
        if ((bytes_read != payload_length) ||
            (memcmp(payload, buffer, bytes_read) != 0))
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
                "ERROR: expected reading %lu bytes but only "
                "received %d bytes\n",
                payload_length,
                bytes_read);
            ret = bytes_read;
            goto exit;
        }
        else
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, " received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }
    } while (1);

exit:
    return ret;
}

int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "%lu bytes written to session peer\n\n", payload_length);
exit:
    return ret;
}


int enc_ssl_send_data(SSL* ssl, const char* data_buf, int data_sz)
{
    int ret = 0;
    int error = 0;
    int bytes_written = 0;
    int total_bytes_written = 0;
    
    while (data_sz != total_bytes_written)
    {
        bytes_written = SSL_write(ssl, &data_buf[total_bytes_written], (size_t)(data_sz - total_bytes_written));

        error = SSL_get_error(ssl, bytes_written);
        if ((error != SSL_ERROR_WANT_WRITE) && (bytes_written <= 0))
        {
            /* Actual error */
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed! SSL_write returned %d, only %d bytes out of %d bytes written successfully\n", error, total_bytes_written, data_sz);
            ret = -1;
            break;
        }

        total_bytes_written += bytes_written;
        ret = total_bytes_written;
    }
            
    enc_print_log(ENC_DEBUG_LEVEL_DUMP, "Successfully sent %d bytes of ssl-data\n", total_bytes_written);

    return ret;
}

int enc_ssl_recv_data(SSL* ssl, char* data_buf)
{
    int ret = -1;
    int error = 0;
    int bytes_read = 0;
    int total_bytes_read = 0;
        
    //memset(data_buf, 0, ENC_BUF_SZ);
    
    do
    {
        bytes_read = SSL_read(ssl, &data_buf[total_bytes_read], (ENC_BUF_SZ - total_bytes_read));
        error = SSL_get_error(ssl, bytes_read);
       
        if ((bytes_read <= 0) && (error != SSL_ERROR_WANT_READ))
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Failed! SSL_read returned error = %d, till now successfully received = %d bytes\n", error, total_bytes_read);
            goto exit;
        }
        else if ((bytes_read > 0) && (error == SSL_ERROR_NONE))
        {
            total_bytes_read += bytes_read;
            ret = total_bytes_read;
            break;
        }
            
        total_bytes_read += bytes_read;

    } while (1);

    ret = total_bytes_read;
        
    enc_print_log(ENC_DEBUG_LEVEL_DUMP, " %d bytes read\n", total_bytes_read);
  
exit: 
    /* Returns the number of bytes read */ 
    return ret;
}

/* Receive a file over a SSL connection */
int enc_ssl_recv_file(SSL* ssl, const char* file_path, char* recv_buff, int *p_recv_sz)
{
    int ret = -1;
    int write_sz;
    int cur_recv_sz;
    int cur_write_sz;
    int file_sz;
    int recv_sz;
    FILE* fp = NULL;
    /* By default the reading happens in global buffer */
    char* read_buff = g_enc_buffer;

    if(p_recv_sz != NULL)
    {
        *p_recv_sz = 0;
    }
    
    /* User may send NULL pointer to receive data into the buffer only */
    if (file_path != NULL)
    {
        fp = sgx_fopen_auto_key(file_path, "wb");
    
        if (fp == NULL)
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "While creating the file: %s\n", file_path);
            goto error_handling;
        }
    }

    if (recv_buff != NULL)
    {
        read_buff = recv_buff;
        enc_print_log(ENC_DEBUG_LEVEL_INFO, "Reading file into the user-provided buffer\n");
    }
        
    //bzero(g_enc_buffer, ENC_BUF_SZ);

    /* First read the file size */
    if(enc_ssl_recv_data(ssl, g_enc_buffer) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(g_enc_buffer);
    if(file_sz < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Receiving file size is < 0\n");
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(enc_ssl_send_data(ssl, g_enc_buffer, 1) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        cur_recv_sz = enc_ssl_recv_data(ssl, &read_buff[recv_sz]);

        if(cur_recv_sz < 0)
        {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Problem while receiving data\n");
            goto error_handling;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            if (file_path != NULL)
            {
                ret = sgx_fwrite(&read_buff[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

                if (ret < 0)
                {
                    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "While writing to the file\n");
                    goto error_handling;
                }
            }
            else
            {
                /* If file path was not mentioned then write to the buffer only */
                ret = cur_recv_sz;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }
    
    if(p_recv_sz != NULL)
    {
        *p_recv_sz = recv_sz;
    }

    enc_print_log(ENC_DEBUG_LEVEL_INFO, "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = 0;

error_handling:
    if (fp != NULL)
    {
        sgx_fclose(fp);
    }

    return ret;
}

/* Send a file over an SSL connection */
int enc_ssl_send_file(SSL* ssl, const char* file_path)
{
	int ret = -1;
	int read_sz;
	int str_sz;
	int send_sz;
	int cur_send_sz;
	int file_sz = 0;
	FILE* fp;

	fp = sgx_fopen_auto_key(file_path, "rb");
	
	if (fp == NULL)
	{
		enc_print_log(ENC_DEBUG_LEVEL_ERROR, "While opening the file\n");
		goto error_handling;
	}
	
	/* Get the file size */
	sgx_fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = sgx_ftell(fp); // get current file pointer
	sgx_fseek(fp, 0, SEEK_SET); // seek back to beginning of file

	//bzero(g_enc_buffer, ENC_BUF_SZ);

    /* Convert the file-size to string */
    str_sz = snprintf(g_enc_buffer, ENC_BUF_SZ, "%d", file_sz);

    if (enc_ssl_send_data(ssl, g_enc_buffer, (str_sz + 1)) != (str_sz + 1))
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (enc_ssl_recv_data(ssl, g_enc_buffer) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != file_sz)
	{
		//bzero(g_enc_buffer, ENC_BUF_SZ);

		read_sz = sgx_fread(g_enc_buffer, 1, ENC_BUF_SZ, fp);

        cur_send_sz = 0;

		while (read_sz != cur_send_sz)
		{
			ret = enc_ssl_send_data(ssl, &g_enc_buffer[cur_send_sz], (read_sz - cur_send_sz));

			if (ret < 0)
			{
 				enc_print_log(ENC_DEBUG_LEVEL_ERROR, "While sending the file: %s\n", file_path);
				goto error_handling;
			}

			cur_send_sz += ret;
		}

        send_sz += cur_send_sz;
	}

	enc_print_log(ENC_DEBUG_LEVEL_INFO, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
	if (fp != NULL)
	{
		sgx_fclose(fp);
	}
    
    return ret;
}
