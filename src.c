// gcc src.c -o src -lcurl -lb64
// ./src -l 8080 -h 127.0.0.1 -p 80 -f -a user:pass
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <assert.h>
#include <strings.h>
#include <curl/curl.h>
#include <b64/cencode.h>
#include <b64/cdecode.h>
#ifdef USE_SYSTEMD
    #include <systemd/sd-daemon.h>
#endif

char authUserPass[128]={0};


#define BUF_SIZE 16384

#define READ  0
#define WRITE 1

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define SYNTAX_ERROR -10

typedef enum {TRUE = 1, FALSE = 0} bool;

int check_ipversion(char * address);
int create_socket(int port);
void sigchld_handler(int signal);
void sigterm_handler(int signal);
void server_loop();
void handle_client(int client_sock, struct sockaddr_storage client_addr);
void forward_data(int source_sock, int destination_sock);
void forward_data_ext(int source_sock, int destination_sock, char *cmd);
int create_connection();
int parse_options(int argc, char *argv[]);
void plog(int priority, const char *format, ...);

int server_sock, client_sock, remote_sock, remote_port = 0;
int connections_processed = 0;
char *bind_addr, *remote_host, *cmd_in, *cmd_out;
bool foreground = FALSE;
bool use_syslog = FALSE;

#define BACKLOG 20 // how many pending connections queue will hold

typedef struct url_parser_url {
    char protocol[8];
    char host[128];
    int port;
    char path[128];
    char query_string[128];
    int host_exists;
    char host_ip[20];
} url_parser_url_t;


/* Program start */
int main(int argc, char *argv[]) {
    int local_port;
    pid_t pid;

    bind_addr = NULL;

    local_port = parse_options(argc, argv);

    if (local_port < 0) {
        printf("Syntax: %s [-b bind_address] -l local_port -h remote_host -p remote_port [-i \"input parser\"] [-o \"output parser\"] [-f (stay in foreground)] [-s (use syslog)]\n", argv[0]);
        return local_port;
    }

    if (use_syslog) {
        openlog("proxy", LOG_PID, LOG_DAEMON);
    }

    if ((server_sock = create_socket(local_port)) < 0) { // start server
        plog(LOG_CRIT, "Cannot run server: %m");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    if (foreground) {
        server_loop();
    } else {
        switch(pid = fork()) {
            case 0: // deamonized child
                server_loop();
                break;
            case -1: // error
                plog(LOG_CRIT, "Cannot daemonize: %m");
                return pid;
            default: // parent
                close(server_sock);
        }
    }

    if (use_syslog) {
        closelog();
    }

    return EXIT_SUCCESS;
}
void encode_auth(char* input){
    char output[128] = {0};
    char* c = output;
    int cnt = 0;
    base64_encodestate s;
    base64_init_encodestate(&s);
    cnt = base64_encode_block(input, strlen(input), c, &s);
    c += cnt;
    cnt = base64_encode_blockend(c, &s);
    c += cnt;
    *(c-1) = 0;
    strcpy(authUserPass,output);
}
/* Parse command line options */
int parse_options(int argc, char *argv[]) {
    int c, local_port = 0;

    while ((c = getopt(argc, argv, "a:b:l:h:p:i:o:fs")) != -1) {
        switch(c) {
            case 'l':
                local_port = atoi(optarg);
                break;
            case 'b':
                bind_addr = optarg;
                break;
            case 'h':
                remote_host = optarg;
                break;
            case 'p':
                remote_port = atoi(optarg);
                break;
            case 'i':
                cmd_in = optarg;
                break;
            case 'o':
                cmd_out = optarg;
                break;
            case 'f':
                foreground = TRUE;
                break;
            case 's':
                use_syslog = TRUE;
                break;
            case 'a':
                encode_auth(optarg);
                break;
        }
    }

    if (local_port && remote_host && remote_port) {
        return local_port;
    } else {
        return SYNTAX_ERROR;
    }
}

int check_ipversion(char * address)
{
/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
         return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}
int url_parser_http(char *url,url_parser_url_t *parsed_url) {
    CURLU *h;
    CURLUcode uc;
    char *host;
    char *path;
    char *port;

    h = curl_url(); /* get a handle to work with */
    if(!h)
    return 1;

    /* parse a full URL */
    uc = curl_url_set(h, CURLUPART_URL, url, 0);
    if(uc)
    goto fail;

    /* extract host name from the parsed URL */
    uc = curl_url_get(h, CURLUPART_HOST, &host, 0);
    if(!uc) {
        // printf("Host name: %s\n", host);
        strcpy(parsed_url->host,host);
        curl_free(host);
    }

    /* extract the path from the parsed URL */
    uc = curl_url_get(h, CURLUPART_PATH, &path, 0);
    if(!uc) {
        // printf("Path: %s\n", path);
        strcpy(parsed_url->path,path);
        curl_free(path);
    }

    /* extract the port from the parsed URL */
    uc = curl_url_get(h, CURLUPART_PORT, &port, 0);
    if(!uc) {
        // printf("Port: %s\n", port);
        parsed_url->port=atoi(port);
        curl_free(port);
    }
    else
        parsed_url->port=80;
    fail:
    curl_url_cleanup(h); /* free url handle */
    return 0;
}

/* Create server socket */
int create_socket(int port) {
    int server_sock, optval = 1;
    int validfamily=0;
    struct addrinfo hints, *res=NULL;
    char portstr[12];

    memset(&hints, 0x00, sizeof(hints));
    server_sock = -1;

    hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* prepare to bind on specified numeric address */
    if (bind_addr != NULL) {
        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if (validfamily = check_ipversion(bind_addr)) {
             hints.ai_family = validfamily;
             hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
        }
    } else {
        /* if bind_address is NULL, will bind to IPv6 wildcard */
        hints.ai_family = AF_INET6; /* Specify IPv6 socket, also allow ipv4 clients */
        hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
    }

    sprintf(portstr, "%d", port);

    /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
    if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0) {
        return CLIENT_RESOLVE_ERROR;
    }

    if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        return SERVER_SOCKET_ERROR;
    }


    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1) {
            close(server_sock);
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, BACKLOG) < 0) {
        return SERVER_LISTEN_ERROR;
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }

    return server_sock;
}

/* Send log message to stderr or syslog */
void plog(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if (use_syslog) {
        vsyslog(priority, format, ap);
    } else {
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
    }

    va_end(ap);
}

/* Update systemd status with connection count */
void update_connection_count()
{
#ifdef USE_SYSTEMD
    sd_notifyf(0, "STATUS=Ready. %d connections processed.\n", connections_processed);
#endif
}

/* Handle finished child process */
void sigchld_handler(int signal) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Handle term signal */
void sigterm_handler(int signal) {
    close(client_sock);
    close(server_sock);
    exit(0);
}

/* Main server loop */
void server_loop() {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

#ifdef USE_SYSTEMD
    sd_notify(0, "READY=1\n");
#endif

    while (TRUE) {
        update_connection_count();
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        } else {
            connections_processed++;
        }
        close(client_sock);
    }

}
#define MAXLEN 1024
int mystrcpy(char* dest, char* src, char delima){
    int len=strlen(src);
    int n=0;
    while(n<len){
        if(src[n]==delima){
            dest[n]=0;
            return n;
        }
        dest[n]=src[n];
        n++;
    }
    return 0;
}
int mystrcpy_http(char* dest, char* src, char* port){
    int len=strlen(src);
    int n=0;
    while(n<len){
        if(src[n]==' '){
            dest[n]=0;
            n=0;
            strcpy(port,"80");
            break;
        }
        if(src[n]==':'){
            dest[n]=0;
            int j=0;
            n+=1;
            while(src[n]!=' '){
                port[j]=src[n];
                j++;
                n++;
            }
            port[j]=0;
            n=0;
            break;
        }
        dest[n]=src[n];
        n++;
    }
    return n;
}
void printf_client_info(struct sockaddr_storage client_addr){
    socklen_t client_len = sizeof(struct sockaddr_storage);

    char hoststr[NI_MAXHOST];
    char portstr[NI_MAXSERV];

    int rc = getnameinfo((struct sockaddr *)&client_addr, 
        client_len, hoststr, sizeof(hoststr), portstr, sizeof(portstr), 
        NI_NUMERICHOST | NI_NUMERICSERV);

    if (rc == 0) 
        printf("%s:%s\t", hoststr, portstr);
}
void generate_http_request(char* src, char* dst,url_parser_url_t *parsed_url){
    sprintf(dst,"GET %s HTTP/1.1\r\n",parsed_url->path);
    sprintf(dst,"%sHost: %s",dst,parsed_url->host);
    if(parsed_url->port!=80)
        sprintf(dst,"%s:%d\r\n",dst,parsed_url->port);
    else
        strcat(dst,"\r\n");
    char *pointer=strstr(src,"User-Agent:");
    if(pointer!=NULL){
        int n=0;
        int len=strlen(dst);
        while(n<MAXLEN){
            dst[len+n]=pointer[n];
            if(pointer[n]==00 && pointer[n+1]==00 && pointer[n+2]==00)break;
            n++;
        }
    }
}
void send_200OK(int client_sock){
    char buff[MAXLEN];
    bzero(buff, MAXLEN);
    strcpy(buff,"HTTP/1.1 200 Connection established\r\n\r\n");
    write(client_sock, buff, strlen(buff));
}
void authorize(int connfd,char *buff){
    char *pointer=NULL;
    while(1){
        pointer=strstr(buff,"Proxy-Authorization");
        if(pointer==NULL){
            bzero(buff, MAXLEN);
            strcpy(buff,"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Type: text/html;charset=utf-8\r\nVary: Accept-Language\r\nContent-Language: en\r\nProxy-Authenticate: Basic realm=\"ultraPort\"\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\nultraPort");            
            write(client_sock, buff, strlen(buff));
            bzero(buff, MAXLEN);
            read(connfd, buff, sizeof(buff));
        }
        else{
            char base64[128]={0};
            mystrcpy(base64,pointer+27,'\r');
            if(strcmp(base64,authUserPass)==0){
                return;
            }
            else{
                bzero(buff, MAXLEN);
                strcpy(buff,"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Type: text/html;charset=utf-8\r\nVary: Accept-Language\r\nContent-Language: en\r\nProxy-Authenticate: Basic realm=\"ultraPort\"\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\nultraPort");            
                write(client_sock, buff, strlen(buff));
                bzero(buff, MAXLEN);
                read(connfd, buff, sizeof(buff));
            }
        }
    }
}
// Function designed for chat between client and server.
void parseRequestMethod(int connfd,struct sockaddr_storage client_addr){
    char buff[MAXLEN]={0};
    bzero(buff, MAXLEN);
    ssize_t length=read(connfd, buff, sizeof(buff));
    if(length==0){
        // printf("READ ERROR\n");
        close(client_sock);
        exit(1);
    }
    char *pointer=strstr(buff,"CONNECT");
    if(pointer!=NULL){
        // printf("CONNECT\t");
        authorize(connfd,buff);
        char hostname[128]={0};
        char dstPort[8]={0};
        int n=mystrcpy(hostname,&pointer[8],':');
        if(n==0){
            // printf("URL ERROR:%s\n",pointer);
            close(client_sock);
            exit(1);
        }
        mystrcpy(dstPort,&pointer[8+n+1],' ');
        // printf_client_info(client_addr);
        strcpy(remote_host,hostname);
        remote_port=atoi(dstPort);
        // printf("Host:%s\t",remote_host);
        // printf("Port:%d\t",remote_port);
        if ((remote_sock = create_connection()) < 0) {
            // plog(LOG_ERR, "Cannot connect to host: %m %s:%d\n",remote_host,remote_port);
            close(remote_sock);
            close(client_sock);
            exit(1);
        }
        send_200OK(client_sock);
        // printf("Connection Established\n");
        return;
    }
    else if((pointer=strstr(buff,"GET"))!=NULL){
        // printf("GET\t");
        authorize(connfd,buff);
        // printf_client_info(client_addr);
        char url[256]={0};
        mystrcpy(url,&pointer[4],' ');
        url_parser_url_t parsed_url;
        int error = url_parser_http(url , &parsed_url);
        strcpy(remote_host,parsed_url.host);
        remote_port=parsed_url.port;
        if ((remote_sock = create_connection()) < 0) {
            // plog(LOG_ERR, "Cannot connect to host: %m %s:%d\n",remote_host,remote_port);
            close(remote_sock);
            close(client_sock);
            exit(1);
        }
        // printf("Host:%s\t",remote_host);
        // printf("Port:%d\t",remote_port);
        // printf("Path:%s\t",parsed_url.path);
        // printf("Connection Established\n");
        char buff1[MAXLEN]={0};
        generate_http_request(buff,buff1,&parsed_url);
        write(remote_sock, buff1, strlen(buff1));
        return;
    }
    else{
        // printf("PARSE ERROR:%s\n",buff);
        close(client_sock);
        exit(1);
    }
    exit(1);
}
/* Handle client connection */
void handle_client(int client_sock, struct sockaddr_storage client_addr)
{
    parseRequestMethod(client_sock,client_addr);
    if (fork() == 0) { // a process forwarding data from client to remote socket
        if (cmd_out) {
            forward_data_ext(client_sock, remote_sock, cmd_out);
        } else {
            forward_data(client_sock, remote_sock);
        }
        exit(0);
    }
    if (fork() == 0) { // a process forwarding data from remote socket to client
        if (cmd_in) {
            forward_data_ext(remote_sock, client_sock, cmd_in);
        } else {
            forward_data(remote_sock, client_sock);
        }
        exit(0);
    }
}

/* Forward data between sockets */
void forward_data(int source_sock, int destination_sock) {
    ssize_t n;

#ifdef USE_SPLICE
    int buf_pipe[2];

    if (pipe(buf_pipe) == -1) {
        plog(LOG_ERR, "pipe: %m");
        exit(CREATE_PIPE_ERROR);
    }

    while ((n = splice(source_sock, NULL, buf_pipe[WRITE], NULL, SSIZE_MAX, SPLICE_F_NONBLOCK|SPLICE_F_MOVE)) > 0) {
        if (splice(buf_pipe[READ], NULL, destination_sock, NULL, SSIZE_MAX, SPLICE_F_MOVE) < 0) {
            plog(LOG_ERR, "write: %m");
            exit(BROKEN_PIPE_ERROR);
        }
    }
#else
    char buffer[BUF_SIZE];

    while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
        send(destination_sock, buffer, n, 0); // send data to output socket
    }
#endif

    if (n < 0) {
        // plog(LOG_ERR, "read: %m");
        exit(BROKEN_PIPE_ERROR);
    }

#ifdef USE_SPLICE
    close(buf_pipe[0]);
    close(buf_pipe[1]);
#endif

    shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
    close(destination_sock);

    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
}

/* Forward data between sockets through external command */
void forward_data_ext(int source_sock, int destination_sock, char *cmd) {
    char buffer[BUF_SIZE];
    int n, i, pipe_in[2], pipe_out[2];

    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) { // create command input and output pipes
        plog(LOG_CRIT, "Cannot create pipe: %m");
        exit(CREATE_PIPE_ERROR);
    }

    if (fork() == 0) {
        dup2(pipe_in[READ], STDIN_FILENO); // replace standard input with input part of pipe_in
        dup2(pipe_out[WRITE], STDOUT_FILENO); // replace standard output with output part of pipe_out
        close(pipe_in[WRITE]); // close unused end of pipe_in
        close(pipe_out[READ]); // close unused end of pipe_out
        n = system(cmd); // execute command
        exit(n);
    } else {
        close(pipe_in[READ]); // no need to read from input pipe here
        close(pipe_out[WRITE]); // no need to write to output pipe here

        while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
            if (write(pipe_in[WRITE], buffer, n) < 0) { // write data to input pipe of external command
                plog(LOG_ERR, "Cannot write to pipe: %m");
                exit(BROKEN_PIPE_ERROR);
            }
            if ((i = read(pipe_out[READ], buffer, BUF_SIZE)) > 0) { // read command output
                send(destination_sock, buffer, i, 0); // send data to output socket
            }
        }

        shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
        close(destination_sock);

        shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
        close(source_sock);
    }
}

/* Create client connection */
int create_connection() {
    struct addrinfo hints, *res=NULL;
    int sock;
    int validfamily=0;
    char portstr[12];

    memset(&hints, 0x00, sizeof(hints));

    hints.ai_flags    = AI_NUMERICSERV; /* numeric service number, not resolve */
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    sprintf(portstr, "%d", remote_port);

    /* check for numeric IP to specify IPv6 or IPv4 socket */
    if (validfamily = check_ipversion(remote_host)) {
         hints.ai_family = validfamily;
         hints.ai_flags |= AI_NUMERICHOST;  /* remote_host is a valid numeric ip, skip resolve */
    }

    /* Check if specified host is valid. Try to resolve address if remote_host is a hostname */
    if (getaddrinfo(remote_host,portstr , &hints, &res) != 0) {
        errno = EFAULT;
        return CLIENT_RESOLVE_ERROR;
    }

    if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        return CLIENT_SOCKET_ERROR;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        return CLIENT_CONNECT_ERROR;
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }

    return sock;
}