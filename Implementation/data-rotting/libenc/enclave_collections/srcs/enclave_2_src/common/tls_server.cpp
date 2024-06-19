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

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "openssl_utility.h"
#include "data_provision.h"
int g_server_socket_fd;
X509* g_certificate = nullptr;
EVP_PKEY* g_pkey = nullptr;
SSL_CONF_CTX* g_ssl_confctx;
SSL_CTX* g_ssl_server_ctx = nullptr;
SSL* g_ssl_session = nullptr;
int g_client_socket_fd = -1;

extern "C"
{
    int ecall_set_up_tls_server(const char* server_port, in_addr_t bc_ip, char *pub_enc_sk_buf, int *p_out_len, int max_result_sz, bool keep_server_up);
    int ecall_tear_down_tls_server();
	sgx_status_t ocall_close(int *ret, int fd);
};

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

void test_enc_loopback_file_transfer(SSL* ssl_session)
{
    char file_name[] = "./enc.tmp.loopback";
    int recv_sz = 0;

    if(enc_ssl_recv_file(ssl_session, file_name, NULL, &recv_sz)){
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error during receiving the file: %s from DO through the established SSL connection\n", file_name);
        return;
    }
    
    if(enc_ssl_send_file(ssl_session, file_name)){
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Error during sending the file: %s to DO through the established SSL connection\n", file_name);

    }
        
    enc_print_log(ENC_DEBUG_LEVEL_ERROR, "Loopback test returned no error, from the enclave..!!\n");

    return;
}

int create_listener_socket(int port, int& server_socket)
{
    int ret = -1;
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
        
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Created server socket fd = %d\n", server_socket);

    if (server_socket < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&reuse,
            sizeof(reuse)) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "setsocket failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Unable to bind socket to the port\n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Unable to open socket for listening\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int handle_communication_until_done(
    in_addr_t bc_ip,
    int& server_socket_fd,
    int& client_socket_fd,
    SSL_CTX*& ssl_server_ctx,
    SSL*& ssl_session,
    char *pub_enc_sk_buf,
    int *p_out_len,
    bool keep_server_up)
{
    int ret = -1;
	int  test_error = 1;
waiting_for_connection_request:
	
    struct sockaddr_in addr;
    uint len = sizeof(addr);

    // reset ssl_session and client_socket_fd to prepare for the new TLS
    // connection
    if (client_socket_fd > 0) 
    {
        ocall_close(&ret, client_socket_fd);
        if (ret != 0) {
            enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "OCALL: error closing client socket before starting a new TLS session.\n");
            goto exit;
        }
    }
    
    SSL_free(ssl_session);
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "waiting for client connection\n");

    client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&addr, &len);

    if (client_socket_fd < 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Unable to accept the client request\n");
        goto exit;
    }

    // create a new SSL structure for a connection
    if ((ssl_session = SSL_new(ssl_server_ctx)) == nullptr)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
               "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    SSL_set_fd(ssl_session, client_socket_fd);

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake

    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "initiating a passive connect SSL_accept\n");
    
    test_error = SSL_accept(ssl_session);
    
    if (test_error <= 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "SSL handshake failed, error(%d)(%d)\n",
					test_error, SSL_get_error(ssl_session, test_error));
        goto exit;
    }

    /* Start the data provision stage */
    if(enc_process_data_provision(ssl_session, pub_enc_sk_buf, p_out_len, bc_ip) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Problem during data-provision stage\n");
        goto exit;
    }

    if (keep_server_up)
        goto waiting_for_connection_request;

    ret = 0;

exit:
    return ret;
}

int ecall_set_up_tls_server(const char* server_port, in_addr_t bc_ip, char *pub_enc_sk_buf, int *p_out_len, int max_result_sz, bool keep_server_up)
{
    int ret = 0;
    unsigned int server_port_number;
    g_ssl_confctx = SSL_CONF_CTX_new();

    if ((g_ssl_server_ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "unable to create a new SSL context\n");
        goto exit;
    }

    if (initalize_ssl_context(g_ssl_confctx, g_ssl_server_ctx) != SGX_SUCCESS)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "unable to create a initialize SSL context\n");
        goto exit;
    }
    SSL_CTX_set_verify(g_ssl_server_ctx, SSL_VERIFY_PEER, &verify_callback);
    
    if (load_tls_certificates_and_keys(g_ssl_server_ctx, g_certificate, g_pkey) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR, 
               " unable to load certificate and private key on the server\n");
        goto exit;
    }
	
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Created keys and certificates\n");
    
    server_port_number = (unsigned int)atoi(server_port); // convert to char* to int
    
    if (create_listener_socket(server_port_number, g_server_socket_fd) != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  " unable to create listener socket on the server\n");
        goto exit;
    }

    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Created server fd = %d within enclave\n", g_server_socket_fd);

    // handle communication
    ret = handle_communication_until_done(
        bc_ip,
        g_server_socket_fd,
        g_client_socket_fd,
        g_ssl_server_ctx,
        g_ssl_session,
        pub_enc_sk_buf,
        p_out_len,
        keep_server_up);
    if (ret != 0)
    {
        enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "server communication error %d\n", ret);
        goto exit;
    }

    /* In success case, return from here */
    return (ret);

exit:
    enc_print_log(ENC_DEBUG_LEVEL_ERROR,  "Error occurred during server setup\n");
    return ecall_tear_down_tls_server();
}

int ecall_tear_down_tls_server()
{
    int ret;
    
    enc_print_log(ENC_DEBUG_LEVEL_INFO,  "Terminating the TLS server\n");
    
    ocall_close(&ret, g_client_socket_fd); // close the socket connections

    if (ret != 0){
        enc_print_log(ENC_DEBUG_LEVEL_INFO,  "OCALL: error closing client socket, error code = %d, but it is not fatal\n", ret);
    }

    ocall_close(&ret, g_server_socket_fd);

    if (ret != 0){
        enc_print_log(ENC_DEBUG_LEVEL_INFO,  "OCALL: error closing server socket, but it is not fatal\n");
    }

    if (g_ssl_session)
    {
        SSL_shutdown(g_ssl_session);
        SSL_free(g_ssl_session);
    }
    if (g_ssl_server_ctx)
        SSL_CTX_free(g_ssl_server_ctx);
    if (g_ssl_confctx)
        SSL_CONF_CTX_free(g_ssl_confctx);
    if (g_certificate)
        X509_free(g_certificate);
    if (g_pkey)
        EVP_PKEY_free(g_pkey);
    return ret;
}

