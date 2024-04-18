/**********************************************************************
 * This file contains the main code for data-owner
 * *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include "sr_info.h"
#include "do_debug.h"
#include "do_common.h"
#include "do_initial_approval.h"
#include "do_data_provision.h"

char    g_buffer[DO_BUF_SZ];
char    *g_do_pri_key_file;
char    *g_do_cert_file;
char    *g_do_priv_data_file;
char    *g_do_tim_lim;
char    *g_libenc_ip;
char    *g_du_ip;
char    g_enc_ip[16] = {0};/*  IP address is maximum 16 bytes long*/
char    g_enc_port[6] = {0};/* Store listening port in string format */
int     g_libenc_port;
int     g_du_port;
int     g_srv_req_id;
int     g_du_sock = -1;

int do_input_check(int argc, char *argv[]);

/* data-owner entry */
int main(int argc, char *argv[])
{
    int ret = -1;

    if(do_input_check(argc, argv) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Input error\n");
        goto stop;
    }

    if(do_initial_approval_stage() != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem in initial approval stage\n");
        goto stop;
    }
    
    print_log(DEBUG_LEVEL_SPECIAL, "Successfully completed initial approval stage with data-user\n");

    /* Wait for some time, before communicating with the enclave, in the mean-time the enclave is getting ready */
    sleep(2);
    
    print_log(DEBUG_LEVEL_SPECIAL, "Starting data-provision stage for the file: %s\n", g_do_priv_data_file);
    
    if(do_data_provision_stage(g_enc_ip, g_enc_port) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem in data-provision stage\n");
        goto stop;
    }
    
    print_log(DEBUG_LEVEL_SPECIAL, "Successfully completed data-provision stage\n");

    ret = 0;
stop:    
    return ret;

}

/* Checks the input from the user  */
int do_input_check(int argc, char *argv[])
{
    int ret = 0;

    if (argc != 10)
    {
        ret = -1;
        
        printf("Usage: data-owner <du-ip> <du-port> <libenc-ip> <libenc-port> <srv-req-id> <do-cert> <do-pri-key> <do-pri-data-file> <exp-tim>\n");
        printf("Inputs:\n");
        printf("      - du-ip           : IP-address of data-user\n");
        printf("      - du-port         : Listening port of data-user\n");
        printf("      - libenc-ip       : IP-address of libenc\n");
        printf("      - libenc-port     : Listening port of libenc\n");
        printf("      - srv-req-id      : ID of the requesting service's ID from data-user(service provider)\n");
        printf("      - do-cert         : Certificate file of data-owner\n");
        printf("      - do-pri-key      : Private key file of data-owner\n");
        printf("      - do-pri-data-file: This file contains the required data in the specified format\n");
        printf("      - time-limit      : Time limit of the given personal data in terms of minutes\n");
    }
    else
    {
        /* Set global variables */
        g_du_ip             = argv[1];
        g_du_port           = atoi(argv[2]);
        g_libenc_ip         = argv[3];
        g_libenc_port       = atoi(argv[4]);
        g_srv_req_id        = atoi(argv[5]);
        g_do_cert_file      = argv[6];
        g_do_pri_key_file   = argv[7];
        g_do_priv_data_file = argv[8];
        g_do_tim_lim        = argv[9];
    }

    return ret;
}


