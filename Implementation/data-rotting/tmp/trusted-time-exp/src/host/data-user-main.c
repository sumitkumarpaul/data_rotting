/**********************************************************************
 * This file contains the main code for data-user
 * *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include "du_business_logic.h"
#include "du_debug.h"
#include "sgx_urts.h" 
#include "du_enc_mang.h"
#include "du_common.h"


char g_buffer[DU_BUF_SZ];
int g_sockfd;
char *g_enc_ip;
char *g_libenc_ip;
char *g_enc_port;
int g_libenc_port;
int du_setup_server(const char* ip, int port);
int du_process_srv_req(void);
void du_finalize_server(void);
int du_input_check(int argc, char *argv[]);
int du_get_approval_process(const char* ip, int port);
int du_send_file(int conn_sock, const char* file_path);
int du_recv_file(int conn_sock, const char* file_path);
int du_verify_enc(int enc_id);
int du_verify_mrenclave(const char* exp_value);
int du_get_edl_file(int enc_id);
int du_deploy_enc_notify_do(int do_sock);

int create_ts_req(const char* ts_req_file);
int verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz);

char g_ts_rsp_buff[2000];

/* data-user entry */
int main(int argc, char *argv[])
{
    int ret;
    FILE *fp = NULL;
    int ts_rsp_file_sz = 0;
    char *ts_rsp_file;

#if 0
    ret = du_input_check(argc, argv);

    if (ret != 0)
    {
        exit(-1);
    }

    if (strcmp(argv[1], "get-approval") == 0)
    {
        ret = du_get_approval_process(argv[2], atoi(argv[3]));
    }
    else
    {
        ret = du_access_do_priv_data();
    }
#endif
    enc_trusted_time_comparison();
#if 0
    ret = create_ts_req("../../time-server/materials/code_gen.tsq");
    
    printf("Please generate the time-stamp response by executing the script. Then enter any key..!!\n");

    getchar();

    ts_rsp_file = "../../time-server/materials/code_gen.tsr";

    fp = fopen(ts_rsp_file,"rb");

    /* Determine the file size */
    fseek(fp, 0L, SEEK_END);
    ts_rsp_file_sz = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if(fread(g_ts_rsp_buff, 1, ts_rsp_file_sz, fp) != ts_rsp_file_sz)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during reading the time-response file\n");
    }

    if (fp != NULL)
    {
        fclose(fp);
    }
   
    ret = verify_ts_rsp(g_ts_rsp_buff, ts_rsp_file_sz);
#endif

    return ret;
}


/* Compares the expected mrenclave value with DO-sent enclave's value */
int du_verify_mrenclave(const char* exp_value)
{
    int ret = -1;
    FILE *fp = NULL;
    char file_char;
    int i;
    int loc;

	bzero(g_buffer, DU_BUF_SZ);
    snprintf(g_buffer, DU_BUF_SZ, "sgx_sign dump -enclave %s -dumpfile ./.tmp.dump > /dev/null\n", DU_RCV_SIGNED_ENC_PATH);
    /* Generate a temporary file using sgx_enclave dump command */
    if (system(g_buffer) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during execution of the shell command\n");
        goto error_handling;
    }

    /* Open the temporary dump file */
    fp = fopen("./.tmp.dump", "rb");
    
    if (fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the dumpfile\n");
        goto error_handling;
    }
    
    /* Dummy read first 80 lines */
    for (i = 0; i < 80; i++)
    {
        fgets(g_buffer, DU_BUF_SZ, fp);
    }

    /* Starting from the beginning of line 81, 162 charecters contain the MRENCLAVE value*/
    /* Read a charecter and match with corresponding char of exp_value */
    for (i = 0; i < 162; i++)
    {
        file_char = fgetc(fp);
    
        if (file_char != exp_value[i])
        {
            print_log(DEBUG_LEVEL_ERROR, "While comparing the mrenclave value.\nAt position: %d expected: '%c', got: '%c'\n", i, exp_value[i], file_char);
            goto error_handling;
        }
    }

    ret = 0;

error_handling:
    /* Close the file */
    if (fp != NULL)
    {
        fclose(fp);
    }

    /* Delete the temporary file */
    system("rm -rf ./.tmp.dump > /dev/null");

    return ret;
}

/* Check whether DO signed and sent proper enclave or not */
int du_verify_enc(int enc_id)
{
    int ret = 0;
    int libenc_sock = -1;
    int cmd_sz;
    struct sockaddr_in libenc_addr;
    char exp_mrenclave[200] = {0};

    libenc_addr.sin_family = AF_INET;
    libenc_addr.sin_port = htons(g_libenc_port);
    libenc_addr.sin_addr.s_addr = inet_addr(g_libenc_ip);

    libenc_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(libenc_sock < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during socket creation for connecting with LibEnc\n");
        goto error_handling;
    }

    /* Connect with the LibEnc */
    ret = connect(libenc_sock, (struct sockaddr*)&libenc_addr, sizeof(libenc_addr));
    
    if(ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during connection with LibEnc\n");
        goto error_handling;
    }

    /* Send command for getting MRENCLAVE */
    bzero(g_buffer, DU_BUF_SZ);
    cmd_sz = snprintf(g_buffer, DU_BUF_SZ, "GET-MRENCLAVE %d ", enc_id);
    
    if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-MRENCLAVE\n");
        goto error_handling;
    }

    if(recv(libenc_sock, exp_mrenclave, 200, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving response of GET-MRENCLAVE\n");
        goto error_handling;
    }

    /* Compare MRENCLAVE values */
    if(du_verify_mrenclave(exp_mrenclave) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "MRENCLAVE is not expected\n");
        goto error_handling;
    }

error_handling:
    if (libenc_sock > 0)
    {
        close(libenc_sock);
    }
    
    return ret;
}

/* Get EDL file */
int du_get_edl_file(int enc_id)
{
    int ret = 0;
    int libenc_sock = -1;
    int cmd_sz;
    struct sockaddr_in libenc_addr;
    char exp_mrenclave[200] = {0};

    libenc_addr.sin_family = AF_INET;
    libenc_addr.sin_port = htons(g_libenc_port);
    libenc_addr.sin_addr.s_addr = inet_addr(g_libenc_ip);

    libenc_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(libenc_sock < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during socket creation for connecting with LibEnc\n");
        goto error_handling;
    }

    /* Connect with the LibEnc */
    ret = connect(libenc_sock, (struct sockaddr*)&libenc_addr, sizeof(libenc_addr));
    
    if(ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during connection with LibEnc\n");
        goto error_handling;
    }

    /* Send command for getting EDL file */
    bzero(g_buffer, DU_BUF_SZ);
    cmd_sz = snprintf(g_buffer, DU_BUF_SZ, "GET-EDL %d ", enc_id);
    
    if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-EDL\n");
        goto error_handling;
    }
    
    if(du_recv_file(libenc_sock, DU_RCV_EDL_FILE_PATH) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving EDL file\n");
        goto error_handling;
    }

error_handling:
    if (libenc_sock > 0)
    {
        close(libenc_sock);
    }
    
    return ret;
}

/* Perform the operation for initial approval stage before actual data transfer */
int du_get_approval_process(const char* ip, int port)
{
    int ret;

    ret = du_setup_server(ip, port);

    if (ret == 0)
    {
        du_process_srv_req();
    }

    du_finalize_server();

    return ret;
}

/* Receive a file over the connected socket */
int du_recv_file(int conn_sock, const char* file_path)
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
        print_log(DEBUG_LEVEL_ERROR, "While creating the empty file\n");
        goto error_handling;
    }
        
    bzero(g_buffer, DU_BUF_SZ);

    /* First read the file size */
    if(recv(conn_sock, g_buffer, DU_BUF_SZ, 0) < 0)
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
    
    print_log(DEBUG_LEVEL_INFO, "Expected file size: %d bytes\n", file_sz);

    /* Send-back a single byte sync message to the server after receiving the file size */
    if(send(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        bzero(g_buffer, DU_BUF_SZ);

        cur_recv_sz = recv(conn_sock, g_buffer, DU_BUF_SZ, 0);

        if(cur_recv_sz < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during reception of the file\n");
            goto error_handling;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            ret = fwrite(&g_buffer[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

            if (ret < 0)
            {
                print_log(DEBUG_LEVEL_ERROR, "While writing to the file\n");
                goto error_handling;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }

    print_log(DEBUG_LEVEL_INFO, "Successfully received the file having size: %d bytes\n", recv_sz);
   
    ret = 0;

error_handling:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/* Send a file over the connected socket */
int du_send_file(int conn_sock, const char* file_path)
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

	bzero(g_buffer, DU_BUF_SZ);

    /* Convert the file-size to string */
    str_sz = snprintf(g_buffer, DU_BUF_SZ, "%d", file_sz);

    if (send(conn_sock, g_buffer, (str_sz + 1), 0) != (str_sz + 1))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from the client */
    if (recv(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message from the client\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != file_sz)
	{
		bzero(g_buffer, DU_BUF_SZ);

		read_sz = fread(g_buffer, 1, DU_BUF_SZ, fp);

        cur_send_sz = 0;

		while (read_sz != cur_send_sz)
		{
			ret = send(conn_sock, &g_buffer[cur_send_sz], (read_sz - cur_send_sz), 0);

			if (ret < 0)
			{
 				print_log(DEBUG_LEVEL_ERROR, "While sending the file\n");
				goto error_handling;
			}

			cur_send_sz += ret;
		}

        send_sz += cur_send_sz;
	}

	print_log(DEBUG_LEVEL_DUMP, "Successfully sent: %d bytes to the client\n", send_sz);
	
    ret = 0;

error_handling:
	if (fp != NULL)
	{
		fclose(fp);
	}
}

/* Finalize server */
void du_finalize_server(void)
{
    /* Free the listening socket */
    if (g_sockfd > 0)
    {
        close(g_sockfd);
        print_log(DEBUG_LEVEL_INFO, "Closing the already created server listening socket\n");
        g_sockfd = -1;
    }

    return;
}

/* Setup server */
int du_setup_server(const char* ip, int port)
{
    int e = -1;
    struct sockaddr_in server_addr;
  
    g_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if(g_sockfd < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during listening socket creation\n");
    }
    else
    {
        if (setsockopt(g_sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during setsockopt with listening port\n");
        }
        else
        {
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = inet_addr(ip);
    
            e = bind(g_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    
            if(e < 0)
            {
                print_log(DEBUG_LEVEL_ERROR, "Problem during binding with: %s:%d\n", ip, port);
                close(g_sockfd);
                print_log(DEBUG_LEVEL_ERROR, "Closing already created socket\n");
                g_sockfd = -1;
            }
            else
            {
                if(listen(g_sockfd, 10) == 0)
                {
                    print_log(DEBUG_LEVEL_INFO, "data-user listening on: %s:%d\n", ip, port);
                    e = 0;
                }
                else
                {
                    print_log(DEBUG_LEVEL_ERROR, "Problem during in listening on: %s:%d\n", ip, port);
                    close(g_sockfd);
                    print_log(DEBUG_LEVEL_ERROR, "Closing already created socket\n");
                    g_sockfd = -1;
                }
            }
        }
    }
    
    return e;
}

/* Process client requests */
int du_process_srv_req(void)
{
    int do_sock;
    int ret = -1;
    int sr_id = INT_MAX;
    int enc_id = INT_MAX;
    struct sockaddr_in do_addr;
    socklen_t addr_size;
    char* cmd;
    char* id_tok;
    int num_srv_avail = sizeof(g_du_business_logics)/sizeof(sr_details); /* Total number of supported services by this data-user */

    addr_size = sizeof(do_addr);
    
    print_log(DEBUG_LEVEL_INFO, "Listening for service request from data-owner...\n");
    
    do_sock = accept(g_sockfd, (struct sockaddr*)&do_addr, &addr_size);

    if (do_sock < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during accepting request from data-owner\n");
        goto error_handling;
    }
    else
    {
        print_log(DEBUG_LEVEL_INFO, "Connected with: %s:%d\n", inet_ntoa(do_addr.sin_addr), ntohs(do_addr.sin_port));
    }

    bzero(g_buffer, DU_BUF_SZ);

    /* Send the data-user's certificate  */
    if (du_send_file(do_sock, DU_CERT_FILE_PATH) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending the data-user's certificate\n");
        goto error_handling;
    }
        
    print_log(DEBUG_LEVEL_INFO, "Sent data-user's certificate\n");

    /* Receive the service request ID */
    if (recv(do_sock, g_buffer, DU_BUF_SZ, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during receving\n");
        goto error_handling;
    }

    id_tok = strtok(g_buffer, " ");

    if (id_tok != NULL)
    {
        sr_id = atoi(id_tok);
    }
    else
    {
        print_log(DEBUG_LEVEL_ERROR, "Received service request is not in proper format\n");
        goto error_handling;
    }

    if (sr_id >= num_srv_avail)
    {
        print_log(DEBUG_LEVEL_ERROR, "Invalid service request number: %d\n", sr_id);
        goto error_handling;
    }
       
    print_log(DEBUG_LEVEL_INFO, "Received service request: %d\n", sr_id);
    
    /* Send the data-usage details for availing this service */ 
    ret = send(do_sock, &g_du_business_logics[sr_id], sizeof(sr_details), 0);
    
    if (ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "While sending data-requirement and usage information\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Successfully sent data-requirement and usage information\n");

    /* Receive the data-owner's certificate file */
    /* This function should also retun error, if
     * data-owner does not agree with data-usage
     * and wants to abort the connection */
    ret = du_recv_file(do_sock, DU_RCV_DO_CERT_PATH);

    if (ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "While receiving data-owner's certificate file\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Successfully received data-owner's certificate file\n");
   
    /* Reveive the signed enclave */ 
    ret = du_recv_file(do_sock, DU_RCV_SIGNED_ENC_PATH);

    if (ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "While receiving signed-enclave file\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Successfully received signed-enclave file\n");

    /* Check whether, the MRENCLAVE value of the received enclave is as expected */
    ret = du_verify_enc(g_du_business_logics[sr_id].enc_id);
    
    if (ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Signed enclave verification error\n");
        goto error_handling;
    }
  
    print_log(DEBUG_LEVEL_INFO, "Successfully verified the signed enclave sent by data-owner\n");

#if 0/* Ideally, this step is not required,
        so commented out. In normal situation
        the data-user should know about the
        OCALL requirement of the "tobe executed"
        enclave and prepare accordingly. */ 
    
    /* Get the edl file */ 
    ret = du_get_edl_file(g_du_business_logics[sr_id].enc_id);
    
    if (ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "During reception of edl file\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Make sure mentioned OCALLs mentioned in *.edl file are\npresent before deploying the enclave.");
#endif
    
    /* Deploy enclave and notify data-owner */
    if (du_deploy_enc_notify_do(do_sock) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during, enclave deployment and notification\n");
        goto error_handling;
    }

    ret = 0;
    print_log(DEBUG_LEVEL_INFO, "Successfully deployed the signed enclave and notified the listening IP and port to the data-owner\n");
    
    sleep(5);
error_handling:
    /* Free the connection socket with data-owner */
    if (do_sock > 0)
    {
        close(do_sock);
        print_log(DEBUG_LEVEL_INFO, "Closing already created connection with the data-owner( %s:%d)\n", inet_ntoa(do_addr.sin_addr), ntohs(do_addr.sin_port));
    }

    du_destroy_enc();

    return ret;
}

/* Checks the input from the user  */
int du_input_check(int argc, char *argv[])
{
    int ret = -1;

    if (argc > 1)
    {
        if (strcmp(argv[1], "get-approval") == 0)
        {
            if (argc == 8)
            {
                ret = 0;
                g_libenc_ip = argv[4];
                g_libenc_port = atoi(argv[5]);
                g_enc_ip = argv[6];
                g_enc_port = argv[7];
        
                goto level_return;
            }
        }
        else if (strcmp(argv[1], "access-data") == 0)
        {
             ret = 0;
             goto level_return;
            /* In this mode, no further input is required*/
        }
        else
        {
            printf("Invalid mode is requested..!!\n");
        }
    }

    printf("Usage: data-user <mode> [inputs]\n");
    printf("Modes:\n");
    printf("      - get-approval: Gets approval from data-owner regarding the usage:\n");
    printf("                      Required inputs are: <listening IP of this data-user> <listening port of this data-user> <LibEnc IP> <LibEnc Port> <Enc IP> <Enc Port>\n");
    printf("      - some-other mode: Performs some other things:\n");
    printf("                      Required inputs sare: something else\n");

level_return:
    return ret;
}

/* Deploy enclave and notify data-owner  */
int du_deploy_enc_notify_do(int do_sock)
{
    int ret = -1;
    int cmd_sz = 0;

    /* Deploy enclave here */
    if (du_setup_enc(DU_RCV_SIGNED_ENC_PATH, g_enc_ip, g_enc_port) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during setup of the received enclave: %s\n", DU_RCV_SIGNED_ENC_PATH);
        goto error_handling;
    }

    /* For the time being, this is a dummy function */
    bzero(g_buffer, DU_BUF_SZ);
        
    cmd_sz = snprintf(g_buffer, DU_BUF_SZ, "%s  %s ", g_enc_ip, g_enc_port);
    
    if(send(do_sock, g_buffer, cmd_sz, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-MRENCLAVE\n");
        goto error_handling;
    }

    ret = 0;

error_handling:

    return ret;
}
