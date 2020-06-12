/*
 * Copyright (c) 2008 Bob Beck <beck@obtuse.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* client.c  - the "classic" example of a socket client */
#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
#include <assert.h>


unsigned long hash(unsigned char *str){
    unsigned long hash = 5381;
    int c;
    while(c = *str++){
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}
static void usage()
{
    extern char * __progname;
    fprintf(stderr, "usage: %s -port proxyportnumber filename\n", __progname);
    exit(1);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in server_sa;
    struct tls_config* tls_client_config = tls_config_new();
    char buffer[80], *ep;
    size_t maxread;
    ssize_t r, rc;
    u_short port;
    u_long p;
    int sd;
    char* filename;
    char* proxyname;
    char* proxyname_with_port;
    char* concatenate_result;
    unsigned long hashed_result;
    if (argc != 4)
        usage();
    if(strcmp(argv[1],"-port") != 0){
        fprintf(stderr,"Argument 1: %s is not -port\n",argv[1]);
    }

    p = strtoul(argv[2], &ep, 10);
    if (*argv[2] == '\0' || *ep != '\0') {
        /* parameter wasn't a number, or was empty */
        fprintf(stderr, "%s - not a number\n", argv[2]);
        usage();
    }
    if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
        /* It's a number, but it either can't fit in an unsigned
         * long, or is too big for an unsigned short
         */
        fprintf(stderr, "%s - value out of range\n", argv[2]);
        usage();
    }
    /* now safe to do this */
    port = p;
    filename = argv[3];
    proxyname = "localhost";
    proxyname_with_port = (char *)malloc(2 + strlen(argv[2]) + strlen(proxyname));
    strcpy(proxyname_with_port, proxyname);
    strcat(proxyname_with_port, ":");
    strcat(proxyname_with_port, argv[2]);
    printf("Proxy Name: %s\n", proxyname_with_port);
    concatenate_result = (char *) malloc(1+ strlen(argv[3]) + strlen(proxyname_with_port));
    strcpy(concatenate_result,argv[3]);
    strcat(concatenate_result,proxyname_with_port);
    hashed_result = hash(concatenate_result);
    printf("Hashed Result: %lu\n",hashed_result);
    tls_config_set_ca_file(tls_client_config,"/home/jackson/CLionProjects/TLSCache/certificates/root.pem");

    struct tls* real_tls_client = tls_client();
    tls_configure(real_tls_client,tls_client_config);

    /*
     * first set up "server_sa" to be the location of the server
     */
    memset(&server_sa, 0, sizeof(server_sa));
    server_sa.sin_family = AF_INET;
    server_sa.sin_port = htons(port);
    char* temp_addr = "127.0.0.1";
    server_sa.sin_addr.s_addr = inet_addr(temp_addr);
    if (server_sa.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address %s\n", temp_addr);
        usage();
    }

    /* ok now get a socket. we don't care where... */
    if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
        err(1, "socket failed");


    /* connect the socket to the server described in "server_sa" */
    if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa))
        == -1)
        err(1, "connect failed");
    if(tls_connect_socket(real_tls_client,sd,temp_addr) == -1){
        err(1,"socket connect failed");
    }
    if(tls_handshake(real_tls_client) == -1){
        printf("Something happened\n");
        err(1, "handshake failed");
    }
    memcpy(buffer,filename,strlen(filename)+1);
    size_t size_of_array = strlen(filename) + 1;
    const void* buf2 = (const void*)buffer;
    size_t amount_of_data_written = 0;
    while(size_of_array > 0){
        ssize_t ret;
        ret = tls_write(real_tls_client,buf2, size_of_array);
        if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
            continue;
        if(ret == -1)
            errx(1, "tls_write: %s", tls_error(real_tls_client));
        buf2 += ret;
        size_of_array -= ret;
        amount_of_data_written += ret;

    }
    // work in progress
    r = -1;
    rc = 0;
    char buf3[80];
    maxread = sizeof(buf3) - 1;
    while((r != 0) && rc < maxread){
        r = tls_read(real_tls_client,buf3 + rc, maxread - rc);
        if(r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
            continue;
        if(r == -1)
            errx(1,"tls_read: %s",tls_error(real_tls_client));
        rc += r;
    }
    buf3[rc] = '\0';

    printf("File received data: %s\n", buf3);
    tls_close(real_tls_client);

    close(sd);
    return(0);
}
