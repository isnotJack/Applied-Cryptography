#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Utility Functions to always send and receive the lenght before the message

bool sendLength(char * msg, int sd){
    int len,lmsg,ret;
    len = strlen(msg)+1;
    lmsg = htons(len);
    ret = send(sd, (void*) &lmsg, sizeof(uint16_t), 0);
    ret = send(sd, (void*) msg, len, 0);
    return ret;
}

bool recvLenght(char * buffer,int sd){
    int len,lmsg,ret;
    ret = recv(sd, (void*)&lmsg, sizeof(uint16_t), 0);
    len = ntohs(lmsg); 
    ret = recv(sd, (void*)buffer, len, 0);
    return ret;
}

