#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>
#include <sys/time.h>
#include <regex.h>
// Utility Functions to always send and receive the lenght before the message
int MAX_LENGTH = 50;
int KEY_LENGTH = 1024;
int PUB_CMD_LENGTH = 129;
int PRIV_CMD_lENGTH = 75;
int US_LENGTH = 20;

bool sendMsg(char * msg, int sd){
    int len,lmsg,ret;
    len = strlen(msg)+1;
    lmsg = htons(len);
    ret = send(sd, (void*) &lmsg, sizeof(uint16_t), 0);
    ret = send(sd, (void*) msg, len, 0);
    return ret;
}

int recvMsg(char * buffer,int sd){
    int len,lmsg,ret;
    ret = recv(sd, (void*)&lmsg, sizeof(uint16_t), 0);
    len = ntohs(lmsg); 
    ret = recv(sd, (void*)buffer, len, 0);
    return len;
}

void keys_generation(char * username){
    //Generazione chiave privata
    char priv_command[PRIV_CMD_lENGTH];
    char pub_command[PUB_CMD_LENGTH];
    if(strcmp(username,"server")==0){
        sprintf(priv_command,"openssl genrsa -out ./keys_server/rsa_privkey_%s.pem 3072",username);
        sprintf(pub_command,"openssl rsa -pubout -in ./keys_server/rsa_privkey_%s.pem -out ./keys_server/rsa_pubkey_%s.pem",username,username);
    }else{
        sprintf(priv_command,"openssl genrsa -out ./keys_clients/rsa_privkey_%s.pem 3072",username);
        sprintf(pub_command,"openssl rsa -pubout -in ./keys_clients/rsa_privkey_%s.pem -out ./keys_clients/rsa_pubkey_%s.pem",username,username);
    }
    
    // Problema dell'injection
    system(priv_command);
    system(pub_command);

}

EVP_PKEY * retrieve_privkey(char * username){
    /* Read a public key from a PEM file */
    EVP_PKEY * privkey;
    char path[100];
    if(strcmp(username,"server")==0){
         sprintf(path, "./keys_server/rsa_privkey_%s.pem",username);
    }else{
        sprintf(path, "./keys_clients/rsa_privkey_%s.pem",username);
    }
    FILE* file = fopen(path, "r");
    if(!file) { 
        printf("Errore nella lettura\n");
        }
    privkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!privkey) { 
        printf("Errore nella read_PrivKey()\n");
        }
    fclose(file);
    return privkey;
}


void retrieve_pubkey(char * username,char * pubkey){
    char path[100];
     if(strcmp(username,"server")==0){
         sprintf(path, "./keys_server/rsa_pubkey_%s.pem",username);
    }else{
        sprintf(path, "./keys_clients/rsa_pubkey_%s.pem",username);
    }
    FILE* file = fopen(path, "r");
    if(!file) { 
        printf("Errore nella lettura\n");
        }
    fread(pubkey,1,KEY_LENGTH,file);
}


void insertFile(char *buffer,int size,int i){
    char path[100];
    sprintf(path,"./keys_server/keys_retrieved/cert_%d.pem",i);
    FILE* file = fopen(path, "w");
    if(!file) { 
        printf("Errore nella lettura\n");
        }
    fwrite(buffer,1,size,file);
}

bool checkInput(char * input){
    regex_t regex;     
    int expr = regcomp(&regex, "^([A-Za-z@.1-9]+)$", REG_EXTENDED);
        // Controlla se l'input soddisfa l'espressione regolare    
    expr = regexec(&regex, input, 0, NULL, 0);    

    regfree(&regex);     
    if (expr != 0){
        printf("Input non valido\n");
        return false;
    }
    return true;
}

// bool checkOverflow(char * input,int max_dim){
//     int input_dim=strlen(input)+1;
//     if (input_dim>max_dim)
//         return true;
//     return false;
// }

