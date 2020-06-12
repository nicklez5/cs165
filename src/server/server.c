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

/* server.c  - the "classic" example of a socket server */

/*
 * compile with gcc -o server server.c
 * or if you are on a crappy version of linux without strlcpy
 * thanks to the bozos who do glibc, do
 * gcc -c strlcpy.c
 * gcc -o server server.c strlcpy.o
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
#include <stdbool.h>
#include <sys/stat.h>

bool file_exists(char *filename){
    struct stat buffer;
    return (stat(filename,&buffer) == 0);
}
static void usage()
{
    extern char * __progname;
    fprintf(stderr, "usage: %s -port portnumber\n", __progname);
    exit(1);
}

static void kidhandler(int signum) {
    /* signal handler for SIGCHLD */
    waitpid(WAIT_ANY, NULL, WNOHANG);
}


int main(int argc,  char *argv[])
{
    struct sockaddr_in sockname, client;
    char buffer[80], *ep;
    struct sigaction sa;
    int sd;
    socklen_t clientlen;
    u_short port;
    pid_t pid;
    u_long p;
    ssize_t r, rc;
    size_t maxread;
    FILE *fp;
    /*
     * first, figure out what port we will listen on - it should
     * be our first parameter.
     */

    if (argc != 3){
        usage();
        errno = 0;
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
    if(strcmp(argv[1],"-port") != 0){
        fprintf(stderr,"Argument 1: %s is not -port\n",argv[1]);
    }
    /* now safe to do this */
    port = p;
    memset(&sockname, 0, sizeof(sockname));
    sockname.sin_family = AF_INET;
    sockname.sin_port = htons(port);
    sockname.sin_addr.s_addr = htonl(INADDR_ANY);
    sd=socket(AF_INET,SOCK_STREAM,0);
    if ( sd == -1)
        err(1, "socket failed");

    if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
        err(1, "bind failed");

    if (listen(sd,3) == -1)
        err(1, "listen failed");

    sa.sa_handler = kidhandler;
    sigemptyset(&sa.sa_mask);

    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
        err(1, "sigaction failed");

    struct tls_config* tls_server_config = tls_config_new();
    tls_config_set_ca_file(tls_server_config,"/home/jackson/CLionProjects/TLSCache/certificates/root.pem");
    struct tls* real_tls_server = tls_server();
    tls_configure(real_tls_server,tls_server_config);
    /*
     * finally - the main loop.  accept connections and deal with 'em
     */
    printf("Server up and listening for connections on port %u\n", port);
    for(;;) {
        int clientsd;
        clientlen = sizeof(&client);
        clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
        if (clientsd == -1)
            err(1, "accept failed");
        pid = fork();
        if (pid == -1)
            err(1, "fork failed");
        if(pid == 0) {
            struct tls *result_data;
            if (tls_accept_socket(real_tls_server, &result_data, clientsd) == -1)
                err(1, "accept socket failed");
            if (tls_handshake(result_data) == -1)
                err(1, "handshake failed");
            r = -1;
            rc = 0;
            maxread = sizeof(buffer) - 1;
            while ((r != 0) && rc < maxread) {
                r = tls_read(result_data, buffer + rc, maxread - rc);
                if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
                    continue;
                if (r == -1)
                    errx(1, "tls_read: %s", tls_error(result_data));
                rc += r;
            }
            buffer[rc] = '\0';
            char *pChar;
            pChar = buffer;
            // open the file
            if (file_exists(pChar)) {
                fp = fopen(pChar, "r");
                if (fp == NULL) {
                    perror("Erroor while opening the file.\n");
                    exit(EXIT_FAILURE);
                }
                printf("The contents of %s file are:\n", pChar);
                char ch;
                while ((ch = fgetc(fp)) != EOF) {
                    char *char_ptr = &ch;
                    const void *temp_void = (const void *) char_ptr;
                    ssize_t ret_1;
                    ret_1 = tls_write(result_data, temp_void, 1);
                    if (ret_1 == TLS_WANT_POLLIN || ret_1 == TLS_WANT_POLLOUT)
                        continue;
                    if (ret_1 == -1)
                        errx(1, "tls_write: %s", tls_error(result_data));
                }
                fclose(fp);
                close(clientsd);
                tls_close(result_data);
                exit(0);
            }
            tls_close(result_data);
        }
        close(clientsd);


    }
    tls_close(real_tls_server);

}
