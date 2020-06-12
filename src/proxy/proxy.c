#include <arpa/inet.h>

#include <netinet/in.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <tls.h>
#include "bloom.h"
bool file_exists(char *filename){
    struct stat buffer;
    return (stat(filename,&buffer) == 0);
}
unsigned int hash(const void *_str){
    const char *str = _str;
    unsigned int hash = 5381;
    char c;
    while((c = *str++)){
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static void usage(){
    extern char * __progname;
    fprintf(stderr, "usage: %s -port portnumber -servername:serverportnumber\n", __progname);
    exit(1);

}
static void kidhandler(int signum) {
    /* signal handler for SIGCHLD */
    waitpid(WAIT_ANY, NULL, WNOHANG);
}
int main(int argc,  char *argv[]){
    //Client variables
    struct sockaddr_in server_sa;
    char buffer[80], *ep;
    size_t maxread;
    ssize_t r, rc;
    FILE *fp;
    bloom_t bloom = bloom_create(8);
    bloom_add_hash(bloom,hash);

    //Mutual variables
    ulong p;
    u_short port;
    int sd;

    //Server variables
    struct sockaddr_in sockname, client;
    struct sigaction sa;
    socklen_t clientlen;
    pid_t pid2;

    //Proxy variable
    struct tls_config* tls_server_config = tls_config_new();
    tls_config_set_ca_file(tls_server_config,"/home/jackson/CLionProjects/TLSCache/certificates/root.pem");
    struct tls* real_tls_server = tls_server();
    tls_configure(real_tls_server,tls_server_config);
    char *server_name;
    u_short server_port;


    if(argc != 4){
        usage();
        errno = 0;
    }
    p = strtoul(argv[2], &ep,10);
    if(*argv[2] == '\0' || *ep != '\0'){
        fprintf(stderr ,"%s - not a number\n", argv[2]);
        usage();
    }
    if((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)){
        fprintf(stderr,"%s - value out of range\n", argv[2]);
        usage();
    }
    char *edit_data = argv[3] + 1;
    char *token_var = strtok(edit_data,":");
    if(token_var){
        server_name = token_var;
    }
    token_var = strtok(NULL,":");
    if(token_var){
        char* number_value = token_var;
        server_port = (u_short)strtoul(number_value,NULL,0);
    }
    port = p;
    memset(&sockname, 0, sizeof(sockname));
    sockname.sin_family = AF_INET;
    sockname.sin_port = htons(port);
    sockname.sin_addr.s_addr = htonl(INADDR_ANY);
    sd=socket(AF_INET,SOCK_STREAM,0);
    if( sd == -1)
        err(1,"socket failed");
    if(bind(sd, (struct sockaddr *) &sockname , sizeof(sockname)) == -1)
        err(1,"bind failed");
    if(listen(sd,3) == -1)
        err(1,"listen failed");

    sa.sa_handler = kidhandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if(sigaction(SIGCHLD,&sa, NULL) == -1)
        err(1,"sigaction failed");
    printf("Server up and listening for connections on port %u\n", port);
    for(;;){
        int clientsd;
        clientlen = sizeof(&client);
        clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
        if(clientsd == -1)
            err(1,"accept failed");
        struct tls* result_data;
        if(tls_accept_socket(real_tls_server, &result_data,clientsd) == -1)
            err(1,"accept socket failed");
        if(tls_handshake(result_data) == -1)
            err(1,"handshake failed");
        r = -1;
        rc = 0;
        char buf3[80];
        maxread = sizeof(buf3) - 1;
        while((r != 0 ) && rc < maxread ){
            r = tls_read(result_data, buf3 + rc, maxread - rc);
            if(r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
                continue;
            if(r == -1)
                errx(1,"tls_read: %s", tls_error(result_data));
            rc += r;
        }
        buf3[rc] = '\0';

        char* pChar;
        pChar = buf3;
        if(bloom_test(bloom,pChar)){
            if(file_exists(pChar)){
                fp = fopen(pChar,"r");
                if(fp == NULL){
                    perror("Error while opening the file.\n");
                    exit(EXIT_FAILURE);
                }
                printf("The contents of %s file are:\n",pChar);
                //send the data to the client.
                char ch;
                while((ch = fgetc(fp)) != EOF){
                    char *char_ptr = &ch;
                    const void *temp_void = (const void *)char_ptr;
                    ssize_t ret_1;
                    ret_1 = tls_write(result_data,temp_void,1);
                    if(ret_1 == TLS_WANT_POLLIN || ret_1 == TLS_WANT_POLLOUT)
                        continue;
                    if(ret_1 == -1)
                        errx(1,"tls_write: %s",tls_error(result_data));
                }
                bloom_add(bloom,pChar);
                fclose(fp);

            }
        }else if( !bloom_test(bloom,pChar) || !file_exists(pChar) ){
            struct tls_config* tls_client_config = tls_config_new();
            tls_config_set_ca_file(tls_client_config,"/home/jackson/CLionProjects/TLSCache/certificates/root.pem");
            struct tls* real_tls_client = tls_client();
            tls_configure(real_tls_client, tls_client_config);
            memset(&server_sa,0,sizeof(server_sa));
            server_sa.sin_family = AF_INET;
            server_sa.sin_port = htons(server_port);
            server_sa.sin_addr.s_addr = inet_addr(server_name);
            if(server_sa.sin_addr.s_addr == INADDR_NONE){
                fprintf(stderr,"Invalid IP address %s\n",server_name);
                usage();
            }
            if((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
                err(1,"socket failed");
            if(connect(sd,(struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
                err(1,"connect failed");
            if(tls_connect_socket(real_tls_client,sd,server_name) == -1)
                err(1,"socket connect failed");
            if(tls_handshake(real_tls_client) == -1)
                err(1,"handshake failed");

            memcpy(buffer,pChar,strlen(pChar)+1);
            size_t size_of_array = strlen(pChar) + 1;
            const void* buf2 = (const void*)buffer;
            size_t amount_of_data_written = 0;
            while(size_of_array > 0){
                ssize_t ret;
                ret = tls_write(real_tls_client,buf2,size_of_array);
                if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
                    continue;
                if(ret == -1)
                    errx(1,"tls_write: %s",tls_error(real_tls_client));
                buf2 += ret;
                size_of_array -= ret;
                amount_of_data_written += ret;
            }

            //created file
            fp = fopen(pChar,"w");

            //read in the file..
            ssize_t r2 = -1;
            ssize_t rc2 = 0;
            char buf4[80];
            size_t maxread1 = sizeof(buf4) - 1;
            while((r2 != 0) && rc2 < maxread1){
                r2 = tls_read(real_tls_client,buf4 + rc2, maxread1 - rc2);
                if(r2 == TLS_WANT_POLLIN || r2 == TLS_WANT_POLLOUT)
                    continue;
                if(r2 == -1)
                    errx(1,"tls_read: %s", tls_error(real_tls_client));
                rc2 += r2;
            }
            buf4[rc2] = '\0';
            if(tls_close(real_tls_client) == -1){
                perror("Closing TLS server failed\n");
                exit(EXIT_FAILURE);
            }
            fprintf(fp,"%s\n",buf4);
            fclose(fp);
            ssize_t ret_2;
            ret_2 = tls_write(result_data,(const void*)buf4,strlen((char*)buf4) + 1);
            if(ret_2 == TLS_WANT_POLLIN || ret_2 == TLS_WANT_POLLOUT)
                continue;
            if(ret_2 == -1)
                errx(1,"tls_write: %s",tls_error(result_data));
            bloom_add(bloom,pChar);

            //send it over to client.
        }
        if(tls_close(result_data) == -1){
            perror("Closing TLS client failed\n");
            exit(EXIT_FAILURE);
        }

    }

}

