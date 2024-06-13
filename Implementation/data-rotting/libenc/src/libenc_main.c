/**********************************************************************
 * This file contains the code of LibEnc
 * *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include "libenc_enc_info.h"
#include "libenc_debug.h"

#define MAX_PATH FILENAME_MAX
#define LIBENC_BUF_SZ 204800U/* Keep buffe-size of all the components same */

char g_buffer[LIBENC_BUF_SZ];
int g_sockfd;
int libenc_setup_server(const char* ip, int port);
int libenc_process_req(void);
void libenc_finalize_server(void);
int libenc_send_file(int conn_sock, const char* file_path);
int libenc_send_file_sz(int conn_sock, const char* file_path);

/* Application entry */
int main(int argc, char *argv[])
{
	int ret;

    if (argc < 3)
	{
		printf("Usage: libenc <ip-address> <port>\n");
		exit(-1);
	}

	ret = libenc_setup_server(argv[1], atoi(argv[2]));

    /* Process the client's requests */
    if(ret == 0)
	{
		while (1)
		{
			if(libenc_process_req() != 0)
            {
                break;
            }
		}
    }
	
	libenc_finalize_server();
    
	return 0;
}
/* Send the size of a file over the connected socket */
int libenc_send_file_sz(int conn_sock, const char* file_path)
{
	int ret = -1;
	int read_sz;
	int str_sz;
	int send_sz;
	int cur_send_sz;
	int file_sz = 0;
	FILE* fp;

	fp = fopen(file_path, "rb");
	
	if (fp == NULL)
	{
		print_log(DEBUG_LEVEL_ERROR, "While opening the file\n");
		goto error_handling;
	}
	
	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file
	print_log(DEBUG_LEVEL_INFO, "Opening file: %s, having size: %d\n", file_path, file_sz);

	/* Convert that to string */
	str_sz = snprintf(g_buffer, LIBENC_BUF_SZ, "%d", file_sz);

	/* File sending is a two step process
	 * At first send the file size */
	if(send(conn_sock, g_buffer, (str_sz + 1), 0) != (str_sz + 1))
    {
 		print_log(DEBUG_LEVEL_ERROR, "While sending the size of the file\n");
		goto error_handling;
    }
	
    ret = 0;

error_handling:
	if (fp != NULL)
	{
		fclose(fp);
	}
    
    return ret;
}

/* Send a file over the connected socket */
int libenc_send_file(int conn_sock, const char* file_path)
{
	int ret = -1;
	int read_sz;
	int str_sz;
	int send_sz;
	int cur_send_sz;
	int file_sz = 0;
	FILE* fp;

	fp = fopen(file_path, "rb");
	
	if (fp == NULL)
	{
		print_log(DEBUG_LEVEL_ERROR, "While opening the file: %s\n", file_path);
		goto error_handling;
	}
	
	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    /* Convert the file-size to string */
    str_sz = snprintf(g_buffer, LIBENC_BUF_SZ, "%d", file_sz);

    if (send(conn_sock, g_buffer, (str_sz + 1), 0) != (str_sz + 1))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot send the file-size properly, so aborting transfer of: %s\n", file_path);
        goto error_handling;
    }
    
    /* Wait for the SYNC message from the client */
    if (recv(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message, so aborting transfer of: %s\n", file_path);
        goto error_handling;
    }
    
    send_sz = 0;

	while (send_sz != file_sz)
	{
		read_sz = fread(g_buffer, 1, LIBENC_BUF_SZ, fp);
	
        if (read_sz < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "While reading the file: %s\n", file_path);
            goto error_handling;
        }

        cur_send_sz = 0;

		while (read_sz != cur_send_sz)
		{
			ret = send(conn_sock, &g_buffer[cur_send_sz], (read_sz - cur_send_sz), 0);

			if (ret < 0)
			{
 				print_log(DEBUG_LEVEL_ERROR, "While sending the file: %s\n", file_path);
				goto error_handling;
			}

			cur_send_sz += ret;
		}

        send_sz += cur_send_sz;
	}

	print_log(DEBUG_LEVEL_INFO, "Successfully sent the file: %s, having size: %d bytes\n", file_path, send_sz);
	ret = 0;

error_handling:
	if (fp != NULL)
	{
		fclose(fp);
	}

}

/* Setup server */
int libenc_setup_server(const char* ip, int port)
{
	int e = -1;
	struct sockaddr_in server_addr;
  
	g_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if(g_sockfd < 0)
	{
		print_log(DEBUG_LEVEL_ERROR, "Problem during socket creation\n");
	}

	if (setsockopt(g_sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
	{
		print_log(DEBUG_LEVEL_ERROR, "Problem during setsockopt\n");
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(ip);
	
	e = bind(g_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	
	if(e < 0)
	{
    	print_log(DEBUG_LEVEL_ERROR, "Problem during binding\n");
		close(g_sockfd);
    	print_log(DEBUG_LEVEL_ERROR, "Closing already created socket\n");
		g_sockfd = -1;
  	}
	
	if(listen(g_sockfd, 10) == 0)
	{
		print_log(DEBUG_LEVEL_INFO, "LibEnc listening on: %s:%d\n", ip, port);
		e = 0;
	}
	else
	{
 		print_log(DEBUG_LEVEL_ERROR, "Problem during in listening\n");
		close(g_sockfd);
    	print_log(DEBUG_LEVEL_ERROR, "Closing already created socket\n");
		g_sockfd = -1;
 	}
	
	
	return e;
}

/* Finalize server */
void libenc_finalize_server(void)
{
	/* Free the listening socket */
	if (g_sockfd > 0)
	{
		close(g_sockfd);
		print_log(DEBUG_LEVEL_INFO, "Closing the already created server listening socket.\n");
		g_sockfd = -1;
	}

	return;
}

/* Process client requests */
int libenc_process_req(void)
{
	int conn_sock;
	int ret = 0;
	int enc_id = INT_MAX;
	struct sockaddr_in client_addr;
	socklen_t addr_size;
	char* cmd;
	char* enc_id_tok;
	int num_enc_avail = sizeof(g_enc_details)/sizeof(enc_details); /* Total number of supported enclaves by this library */

	addr_size = sizeof(client_addr);
	
	print_log(DEBUG_LEVEL_INFO, "Listening for commands from clients...\n");
	
	conn_sock = accept(g_sockfd, (struct sockaddr*)&client_addr, &addr_size);

	if (conn_sock < 0)
	{
 		print_log(DEBUG_LEVEL_ERROR, "Problem during accepting request from client\n");
		goto error_handling;
	}
	else
	{
		print_log(DEBUG_LEVEL_INFO, "Connected with: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
	}

	if (recv(conn_sock, g_buffer, LIBENC_BUF_SZ, 0) < 0)
	{
 		print_log(DEBUG_LEVEL_ERROR, "Error during receving the command from client\n");
		goto error_handling;
    }

    print_log(DEBUG_LEVEL_INFO, "Received command: %s\n", g_buffer);

	cmd = strtok(g_buffer, " ");
	enc_id_tok = strtok(NULL, " ");

	if (enc_id_tok != NULL)
	{
		enc_id = atoi(enc_id_tok);
	}
    else
    {
        enc_id = 0;
    }

	if (enc_id >= num_enc_avail)
	{
        /* Send usage information to the client */
		send(conn_sock, g_libenc_usage_info, sizeof(g_libenc_usage_info), 0);
 		print_log(DEBUG_LEVEL_ERROR, "Invalid enclave number requested: %d\n", enc_id);
		goto error_handling;
	}

	if (strncmp(cmd, "GET-ENC", sizeof("GET-ENC") - 1) == 0)
	{
		ret = libenc_send_file(conn_sock, g_enc_details[enc_id].enc_path);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending enclave(%d)\n", enc_id);
			goto error_handling;
		}
	}
	else if (strncmp(cmd, "GET-EDL", sizeof("GET-EDL") - 1) == 0)
	{
		ret = libenc_send_file(conn_sock, g_enc_details[enc_id].edl_path);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending edl file of enclave(%d)\n", enc_id);
			goto error_handling;
		}
	}
	else if (strncmp(cmd, "GET-CNF", sizeof("GET-CNF") - 1) == 0)
	{
		ret = libenc_send_file(conn_sock, g_enc_details[enc_id].cfg_path);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending configuration file of enclave(%d)\n", enc_id);
			goto error_handling;
		}
	}
	else if (strncmp(cmd, "GET-SRC", sizeof("GET-SRC") - 1) == 0)
	{
		ret = libenc_send_file(conn_sock, g_enc_details[enc_id].src_path);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending source files of enclave(%d)\n", enc_id);
			goto error_handling;
		}
	}
    else if (strncmp(cmd, "GET-ENC-SZ", sizeof("GET-ENC-SZ") - 1) == 0)
	{
		ret = libenc_send_file_sz(conn_sock, g_enc_details[enc_id].enc_path);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending the size of enclave(%d)\n", enc_id);
			goto error_handling;
		}
		else
		{
 			print_log(DEBUG_LEVEL_INFO, "Successfully sent the size of enclave(%d)\n", enc_id);
		}
	}
	else if (strncmp(cmd, "GET-EDL-SZ", sizeof("GET-EDL-SZ") - 1) == 0)
	{
		ret = libenc_send_file_sz(conn_sock, g_enc_details[enc_id].edl_path);

		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending the size of the edl file corresponding to the enclave(%d)\n", enc_id);
			goto error_handling;
		}
		else
		{
 			print_log(DEBUG_LEVEL_INFO, "Successfully sent the size of the edl file corresponding to the enclave(%d)\n", enc_id);
		}
	}
	else if (strncmp(cmd, "GET-MRENCLAVE", sizeof("GET-MRENCLAVE") - 1) == 0)
	{
		ret = send(conn_sock, g_enc_details[enc_id].mrenclave, sizeof(g_enc_details[0].mrenclave), 0);
	
		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending enclave(%d) MRENCLAVE value\n", enc_id);
			goto error_handling;
		}
		else
		{
 			print_log(DEBUG_LEVEL_INFO, "Successfully sent MRENCLAVE value of enclave(%d)\n", enc_id);
		}
	}
	else if (strncmp(cmd, "GET-DESC", sizeof("GET-DESC") - 1) == 0)
	{
		ret = send(conn_sock, g_enc_details[enc_id].desc, sizeof(g_enc_details[0].desc), 0);
		
		if (ret < 0)
		{
 			print_log(DEBUG_LEVEL_ERROR, "While sending enclave(%d)'s description\n", enc_id);
			goto error_handling;
		}
		else
		{
 			print_log(DEBUG_LEVEL_INFO, "Successfully sent enclave(%d)'s description\n", enc_id);
		}
	}
	else if (strncmp(cmd, "STOP", sizeof("STOP")-1) == 0)
    {
 	    print_log(DEBUG_LEVEL_INFO, "Stopping enclave library after getting the command: STOP\n");
        ret = -1;
		goto error_handling;
    }
	else
	{
        /* Send usage information to the client */
		send(conn_sock, g_libenc_usage_info, sizeof(g_libenc_usage_info), 0);
		print_log(DEBUG_LEVEL_ERROR, "Received unknown command: %s\n", g_buffer);
	}

    if (ret >= 0)
    {
        ret = 0;
    }

error_handling:
	/* Free the connection socket */
	if (conn_sock > 0)
	{
		close(conn_sock);
		print_log(DEBUG_LEVEL_INFO, "Disconnected from: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
	}

    return ret;

}


