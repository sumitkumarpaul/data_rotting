/**********************************************************************
 * This file contains the code of LibEnc
 * *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include "time_server_debug.h"

#define MAX_PATH FILENAME_MAX
#define TIME_SERVER_BUF_SZ 2048U/* Keep buffe-size of all the components same */

char g_buffer[TIME_SERVER_BUF_SZ];
int g_sockfd;
int ts_setup_server(const char* ip, int port);
int ts_process_req(void);
void ts_finalize_server(void);
int ts_send_file(int conn_sock, const char* file_path);
int ts_recv_file(int conn_sock, const char* file_path);

/* Application entry */
int main(int argc, char *argv[])
{
	int ret;

    if (argc < 3)
	{
		printf("Usage: time-server <ip-address> <port>\n");
		exit(-1);
	}

	ret = ts_setup_server(argv[1], atoi(argv[2]));

    /* Process the client's requests */
    if(ret == 0)
	{
		while (1)
		{
			if (ts_process_req() != 0)
            {
                break;
            }
		}
    }
	
	ts_finalize_server();
    
	return 0;
}

/* Setup server */
int ts_setup_server(const char* ip, int port)
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
		print_log(DEBUG_LEVEL_INFO, "Trusted time-server listening on: %s:%d\n", ip, port);
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
void ts_finalize_server(void)
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


/* Receive a file over the connected socket */
int ts_recv_file(int conn_sock, const char* file_path)
{
    int ret = -1;
    int write_sz;
    int cur_recv_sz;
    int cur_write_sz;
    int file_sz;
    int recv_sz;
    FILE* fp;

    fp = fopen(file_path, "wb");
    
    if (fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "While creating the file: %s\n", file_path);
        goto error_handling;
    }
        
    bzero(g_buffer, TIME_SERVER_BUF_SZ);

    /* First read the file size */
    if(recv(conn_sock, g_buffer, TIME_SERVER_BUF_SZ, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(g_buffer);
    if(file_sz < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Receiving file size is < 0\n");
        goto error_handling;
    }
    else if (file_sz < 5)
    {
        print_log(DEBUG_LEVEL_INFO, "Receiving file size is < 5\n");
        ret = 4;
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(send(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        bzero(g_buffer, TIME_SERVER_BUF_SZ);

        cur_recv_sz = recv(conn_sock, g_buffer, TIME_SERVER_BUF_SZ, 0);

        if(cur_recv_sz < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem while receiving data for the file: %s\n", g_buffer);
            goto error_handling;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            ret = fwrite(&g_buffer[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

            if (ret < 0)
            {
                print_log(DEBUG_LEVEL_ERROR, "While writing to the file: %s\n", g_buffer);
                goto error_handling;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = recv_sz;

error_handling:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/* Send a file over the connected socket */
int ts_send_file(int conn_sock, const char* file_path)
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

	bzero(g_buffer, TIME_SERVER_BUF_SZ);

    /* Convert the file-size to string */
    str_sz = snprintf(g_buffer, TIME_SERVER_BUF_SZ, "%d", file_sz);

    if (send(conn_sock, g_buffer, (str_sz + 1), 0) != (str_sz + 1))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (recv(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != file_sz)
	{
		bzero(g_buffer, TIME_SERVER_BUF_SZ);

		read_sz = fread(g_buffer, 1, TIME_SERVER_BUF_SZ, fp);

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

	print_log(DEBUG_LEVEL_INFO, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
	if (fp != NULL)
	{
		fclose(fp);
	}
    
    return ret;
}

/* Process timestamping requests */
int ts_process_req(void)
{
	int conn_sock;
	int ret = 0;
	struct sockaddr_in client_addr;
	socklen_t addr_size;
    int recv_sz;

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

	bzero(g_buffer, TIME_SERVER_BUF_SZ);

    recv_sz = ts_recv_file(conn_sock, "./materials/ts.req");

    if (recv_sz < 0)
    {
 		print_log(DEBUG_LEVEL_ERROR, "Error during receiving the time-stamp request file\n");
		goto error_handling;
    }
    else if (recv_sz < 5)
    {
 		print_log(DEBUG_LEVEL_INFO, "Stopping time-stamp server as per the request\n");
        ret = -1;
		goto error_handling;
    }
    
    /* Form the system command */
	bzero(g_buffer, TIME_SERVER_BUF_SZ);

    /* Create the command */
    snprintf(g_buffer, TIME_SERVER_BUF_SZ, "openssl ts -reply -config ./materials/sample_ts_signer_conf.cnf -queryfile ./materials/ts.req -inkey ./materials/sample_ts_pri_key.pem -signer ./materials/sample_ts_cert.pem -out ./materials/ts.tsr  > /dev/null 2>&1\n");
    
    /* Generate the time response file */
    if (system(g_buffer) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during execution of the shell command: %s\n", g_buffer);
		goto error_handling;
    }

    /* Send time-stamp response */
    if (ts_send_file(conn_sock, "./materials/ts.tsr") != 0)
    {
 		print_log(DEBUG_LEVEL_ERROR, "Error during sending the time-stamp response file\n");
		goto error_handling;
    }
		
    print_log(DEBUG_LEVEL_INFO, "Successfully sent the timestamping response\n");

error_handling:
	/* Free the connection socket */
	if (conn_sock > 0)
	{
		close(conn_sock);
		print_log(DEBUG_LEVEL_INFO, "Disconnected from: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
	}

	return ret;
}

