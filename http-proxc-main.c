#include <arpa/inet.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHUNK_SIZE 256

int recv_timeout(int s, char *reply, float timeout)
{
    int size_recv, total_size = 0;
    struct timeval begin, now;
    char chunk[CHUNK_SIZE];
    double timediff;

    //make socket non blocking
    fcntl(s, F_SETFL, O_NONBLOCK);

    //beginning time
    gettimeofday(&begin, NULL);

    while (1)
    {
        gettimeofday(&now, NULL);

        //time elapsed in seconds
        timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);

        //if you got some data, then break after timeout
        if (total_size > 0 && timediff > timeout)
        {
            break;
        }

        //if you got no data at all, wait a little longer, twice the timeout
        else if (timediff > timeout * 2)
        {
            break;
        }

        memset(chunk, 0, CHUNK_SIZE); //clear the variable
        if ((size_recv = (int)recv(s, chunk, CHUNK_SIZE, 0)) <= 0)
        {
            //if nothing was received then we want to wait a little before trying again, 0.1 seconds
            usleep(100000);
        }
        else
        {
            printf("Recieved Chunk\n");
            memcpy(&reply[total_size], chunk, size_recv);
            total_size += size_recv;
            //printf("%s" , chunk);
            //reset beginning time
            gettimeofday(&begin, NULL);
        }
    }
    return total_size;
}

void error(char *msg) {
    perror(msg);
    exit(1);
}

char *getaddrbyhost6(char* hostname) {
    struct hostent *server;
    server = gethostbyname2(hostname, AF_INET);
    if (server == NULL) {
        herror("gethostbyname");
        return NULL;
    }
    printf("%s\n", inet_ntoa(*((struct in_addr *)server->h_addr)));

    char *addr = malloc(256);
    strcpy(addr, inet_ntoa(*((struct in_addr *)server->h_addr)));
    char *orig = addr;
    int len = (int)(strchr(addr, '.') - addr);
    char byte1[4];
    memset(byte1, '\0', 4);
    strncpy(byte1, addr, len);
    addr = strchr(addr, '.') + 1;

    len = (int)(strchr(addr, '.') - addr);
    char byte2[4];
    memset(byte2, '\0', 4);
    strncpy(byte2, addr, len);
    addr = strchr(addr, '.') + 1;

    len = (int)(strchr(addr, '.') - addr);
    char byte3[4];
    memset(byte3, '\0', 4);
    strncpy(byte3, addr, len);
    addr = strchr(addr, '.') + 1;

    char byte4[4];
    memset(byte4, '\0', 4);
    strcpy(byte4, addr);

    printf("%s %s %s %s\n", byte1, byte2, byte3, byte4);

    int a1 = atoi(byte1) / 16;
    int a3 = atoi(byte2) / 16;
    int a5 = atoi(byte3) / 16;
    int a7 = atoi(byte4) / 16;
    int a2 = atoi(byte1) % 16;
    int a4 = atoi(byte2) % 16;
    int a6 = atoi(byte3) % 16;
    int a8 = atoi(byte4) % 16;

    char *newAddr = malloc(256);

    sprintf(newAddr, "::ffff:%x%x%x%x:%x%x%x%x", a1, a2, a3, a4, a5, a6, a7, a8);

    free(orig);

    return newAddr;
}

int recv_all(int socket, char *buffer)
{
    fcntl(socket, F_SETFL, O_NONBLOCK);

    int i = 0, total_size = 0;
    char chunk[CHUNK_SIZE];
    memset(chunk, 0, CHUNK_SIZE);
    while((i = recv(socket, chunk, CHUNK_SIZE, 0)) <= 0) {}
    printf("Red Robin1 %s\n", chunk);
    memcpy(buffer + total_size, chunk, i);
    printf("Red Robin2\n");
    total_size += i;
    memset(chunk, 0, CHUNK_SIZE);

    while((i = recv(socket, chunk, CHUNK_SIZE, 0)) > 0) {
        memcpy(buffer + total_size, chunk, i);
        total_size += i;
        memset(chunk, 0, CHUNK_SIZE);
    }

    return total_size;
}

int send_all(int socket, void *buffer, size_t length)
{
    char *ptr = (char*) buffer;
    while (length > 0)
    {
        int i = send(socket, ptr, length, 0);
        if (i < 1) return 0;
        ptr += i;
        length -= i;
    }
    return 1;
}

void *connection_handler(void *socket_desc)
{
    int n;
    int sockfd;
    int ctc = 0;
    char *rbuff = malloc(10000);
    memset(rbuff, '\0', 10000);
    char host[1000];
    char prt[7];
    memset(host, '\0', 1000);
    memset(prt, '\0', 7);

    //Sockets Layer Call: recv()
    while((n = recv_timeout(*(int *)socket_desc, rbuff, 0.1f)) == 0) {}
    printf("Message from client: %s\n", rbuff);

    //Sockets Layer Call: send()

    //parse out address and port here
    if(!ctc) {
    ctc = 1;
    void *start = strstr(rbuff, "Host: ") + 6;
    void *end = strstr(start, "\r");
    int len = (int)(end - start);
    strncpy(host, start, len);
    printf("Host: %s\n", host);
    if(strstr(host, ":")) {
        start = strstr(host, ":");
        strcpy(prt, start);
    } else {
        strcpy(prt, "80");
    }

    start = strstr(rbuff, "Host: ") + 6;
    end = strstr(start, "\r");
    len = (int)(end - start);
    memset(host, '\0', 1000);
    strncpy(host, start, len);

    printf("Host: %s, Port %s\n", host, prt);

    //----------------------------------------------
    
    //Sockets Layer Call: socket()

    struct addrinfo hints, *servinfo, *p;
    int rv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;
    if ((rv = getaddrinfo(host, prt, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    }
    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("connect");
            close(sockfd);
            continue;
        }
        break; // if we get here, we must have connected successfully
    }

    } else {
    }
    //Sockets Layer Call: send()
    int nn;
    nn = send_all(sockfd, rbuff, n);
    if (nn < 0) {
        error("ERROR writing to socket");
    }
    char buffer[100000];
    memset(buffer, '\0', 100000);
    
    //Sockets Layer Call: recv()
    while((nn = recv_timeout(sockfd, buffer, 0.1f)) == 0) {}
    if (nn < 0) {
        error("ERROR reading from socket");
    }
    printf("Message from server: %s\n", buffer);

    //----------------------------------------------

    n = send_all(*(int *)socket_desc, buffer, nn);
    printf("Sent: %i\n", n);
    if (n < 0) {
        error("ERROR writing to socket");
    }
    //}
    free(rbuff);
    close(sockfd);
    close(*(int *)socket_desc);
    return NULL;
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, *new_sock;;
    socklen_t clilen;
    struct sockaddr_in6 serv_addr, cli_addr;
    char client_addr_ipv6[100];

    printf("\nIPv6 TCP Server Started...\n");
    
    //Sockets Layer Call: socket()
    sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin6_flowinfo = 0;
    serv_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &serv_addr.sin6_addr);
    serv_addr.sin6_port = htons(9002);

    
    //Sockets Layer Call: bind()
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR on binding");
    }
    //Sockets Layer Call: listen()
    listen(sockfd, 3);
    clilen = sizeof(cli_addr);
    
    //Sockets Layer Call: accept()
    while ((newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen)))
    {
        pthread_t thread;
        new_sock = malloc(1);
        *new_sock = newsockfd;
        printf("New Connection\n");
        if (pthread_create(&thread, NULL, connection_handler, (void *)new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }
    }
    
    //Sockets Layer Call: close()
    close(sockfd);
    close(newsockfd);
    
    return 0;
}