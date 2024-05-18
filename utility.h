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


int MAX_LENGTH = 50;
int KEY_LENGTH = 1024;
int PUB_CMD_LENGTH = 129;
int PRIV_CMD_lENGTH = 75;
int US_LENGTH = 20;


// Utility Functions to send and receive the lenght before the message
bool sendMsg(char * msg, int sd){
    int ret;
    long len,lmsg;
    len = strlen(msg)+1;
    lmsg = htonl(len);
    ret = send(sd, (void*) &lmsg, sizeof(uint32_t), 0);
    ret = send(sd, (void*) msg, len, 0);
    return ret;
}


long recvMsg(char * buffer,int sd){
    int ret;
    long len,lmsg;
    ret = recv(sd, (void*)&lmsg, sizeof(uint32_t), 0);
    if(ret==-1){
        return ret;
    }
    len = ntohl(lmsg); 
    ret = recv(sd, (void*)buffer, len, 0);
    if(ret==-1){
        return ret;
    }
    return len;
}

//Generation of P and G for DH 
void DH_parameter_generation(){
    char command[MAX_LENGTH];
    FILE * file=fopen("dh_param.pem","r");
    if(file){
        fclose(file);
    }else{
    sprintf(command,"openssl dhparam -out dh_param.pem -2 -C 2048");
    system(command);
    }   
}


void DH_PubPriv(EVP_PKEY* dh_params, EVP_PKEY ** my_prvkey,EVP_PKEY_CTX * DH_ctx){
    EVP_PKEY_keygen_init(DH_ctx);
    EVP_PKEY_keygen(DH_ctx, my_prvkey); //Generate both 'a' and 'G^a'

}

int Hash(unsigned char * digest, unsigned char *msg ,int msg_len){
    int digestlen;
    EVP_MD_CTX* ctx;
    ctx = EVP_MD_CTX_new();
    /* Hashing (initialization + single update + finalization */
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, (unsigned char*)msg, msg_len);
    EVP_DigestFinal(ctx, digest, &digestlen);
    /* Context deallocation */
    EVP_MD_CTX_free(ctx);
    return digestlen;
}

// bool deserialize(BIO * bio, EVP_PKEY * DH_client_keys){
//     // Lettura della chiave pubblica dal BIO
//     if (!bio) {
//         return false;
//     }
//     DH_client_keys= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
//     if (!DH_client_keys) {
//        return false;
//     }
//     return true;
// }

// long serialize (EVP_PKEY * key,char ** buffer){
//      BIO *bio = BIO_new(BIO_s_mem()); // Creazione di un BIO in memoria
//     //da mettere in una funzione
//     if (!bio) {
//         return -1; // Errore nella creazione del BIO
//     }
//     // Scrittura della chiave pubblica nel BIO
//     if (!PEM_write_bio_PUBKEY(bio, key)) {
//         BIO_free(bio); // Liberare la memoria del BIO
//         perror("Errore sulla PEM_WRITE_BIO \n");
//         return -1; // Errore nella scrittura della chiave pubblica nel BIO
//     }
//     // Ottieni il puntatore al buffer di dati BIO
//     long buffer_length = BIO_get_mem_data(bio, &buffer);

//     printf("Buffer dentro serialize %p \n", *buffer);
//     BIO_free(bio); // Liberare la memoria del BIO
//     return buffer_length;
// }

 int Verify_Signature(EVP_PKEY * DH_keys,EVP_PKEY * pubkey, unsigned char * signature, int signature_length){
     EVP_MD_CTX* VER_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(VER_ctx, EVP_sha256());
    BIO *bio = BIO_new(BIO_s_mem()); // Creazione di un BIO in memoria
    if (!bio) {
        return -1; // Errore nella creazione del BIO
    }

    // Scrittura della chiave pubblica nel BIO
    if (!PEM_write_bio_PUBKEY(bio, DH_keys)) {
        BIO_free(bio); // Liberare la memoria del BIO
        return -1; // Errore nella scrittura della chiave pubblica nel BIO
    }

    // Ottieni il puntatore al buffer di dati BIO
    char *buffer_data;
    long buffer_length = BIO_get_mem_data(bio, &buffer_data);
    
    EVP_VerifyUpdate(VER_ctx, buffer_data, buffer_length);
    int ret = EVP_VerifyFinal(VER_ctx, signature,signature_length, pubkey);
    EVP_MD_CTX_free(VER_ctx);
    BIO_free(bio); 
    return ret;
 }

int Digital_Signature(EVP_PKEY * priv_key, EVP_PKEY * DH_keys, unsigned char * signature){

    int signature_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    char * buffer;
    BIO *bio = BIO_new(BIO_s_mem()); // Creazione di un BIO in memoria
    //da mettere in una funzione
    if (!bio) {
        return -1; // Errore nella creazione del BIO
    }
   
    // Scrittura della chiave pubblica nel BIO
    if (!PEM_write_bio_PUBKEY(bio, DH_keys)) {
        BIO_free(bio); // Liberare la memoria del BIO
        printf("PEM WRITE ERROR \n");
        return -1; // Errore nella scrittura della chiave pubblica nel BIO
    }
    
    // Ottieni il puntatore al buffer di dati BIO
    long buffer_length = BIO_get_mem_data(bio, &buffer);

    EVP_SignUpdate(ctx, (unsigned char*)buffer,buffer_length);
    EVP_SignFinal(ctx, signature, &signature_len,priv_key);
    printf("Signature done \n");
    EVP_MD_CTX_free(ctx);
    BIO_free(bio); // Liberare la memoria del BIO
    return signature_len;
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
        printf("Error opening the file1\n");
        exit(1);
    }
    privkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!privkey) { 
        printf("Error reading the private key\n");
        exit(1);
    }
    fclose(file);
    return privkey;
}

EVP_PKEY * retrieve_pubkey(char * username, int sd){
    /* Read a public key from a PEM file */
    EVP_PKEY * pubkey;
    char path[100];
    if(strcmp(username,"server")==0 && sd<0){
         sprintf(path, "./keys_server/rsa_pubkey_%s.pem",username);
    }else if(strcmp(username,"server")==0 && sd>=0){
        sprintf(path, "./keys_server/keys_retrieved/cert_%d.pem",sd);
    }
    else{
        sprintf(path, "./keys_clients/rsa_pubkey_%s.pem",username);
    }
    FILE* file = fopen(path, "r");
    if(!file) { 
        printf("Error opening the file2\n");
        exit(1);
    }
    pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubkey) { 
        printf("Error reading the public key\n");
        exit(1);
    }
    fclose(file);
    return pubkey;
}

// void retrieve_pubkey(char * username, char * pubkey){
//     char path[100];
//      if(strcmp(username,"server")==0){
//          sprintf(path, "./keys_server/rsa_pubkey_%s.pem",username);
//     }else{
//         sprintf(path, "./keys_clients/rsa_pubkey_%s.pem",username);
//     }
//     FILE* file = fopen(path, "r");
//     if(!file) { 
//         printf("Error opening the file\n");
//         exit(1);
//     }
//     fread(pubkey,1,KEY_LENGTH,file);
// }


void insertFile(char *buffer,int size, int i){
    char path[100];
    sprintf(path,"./keys_server/keys_retrieved/cert_%d.pem",i);
    FILE* file = fopen(path, "w");
    if(!file) { 
        printf("Error opening the file3\n");
        exit(1);
    }
    BIO *bio = BIO_new_mem_buf(buffer, size);
    if (!bio) {
        // Errore nella creazione del BIO
        return ;
    }
    // Lettura della chiave pubblica dal BIO
    EVP_PKEY *public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!public_key) {
        // Errore nella lettura della chiave pubblica dal BIO
        BIO_free(bio); // Liberare la memoria del BIO
        return ;
    }
    // Liberare la memoria del BIO
    BIO_free(bio);

    PEM_write_PUBKEY(file,public_key);
    fclose(file);
}

bool checkInput(char * input){
    regex_t regex;     
    int expr = regcomp(&regex, "^([A-Za-z@.0-9]+)$", REG_EXTENDED);
        // Controlla se l'input soddisfa l'espressione regolare    
    expr = regexec(&regex, input, 0, NULL, 0);    

    regfree(&regex);     
    if (expr != 0){
        printf("Invalid input\n");
        return false;
    }
    return true;
}

bool send_public_key(int socket, EVP_PKEY *public_key) {
    BIO *bio = BIO_new(BIO_s_mem()); // Creazione di un BIO in memoria
    if (!bio) {
        return 1; // Errore nella creazione del BIO
    }
 
    // Scrittura della chiave pubblica nel BIO
    if (!PEM_write_bio_PUBKEY(bio, public_key)) {
        BIO_free(bio); // Liberare la memoria del BIO
        return 1; // Errore nella scrittura della chiave pubblica nel BIO
    }
 
    // Ottieni il puntatore al buffer di dati BIO
    char *buffer_data;
    long buffer_length = BIO_get_mem_data(bio, &buffer_data);
    long lmsg=htonl(buffer_length);
    send(socket, (void*) &lmsg, sizeof(uint32_t), 0);
    // Invia la chiave pubblica sul socket
    send(socket,(void *) buffer_data,buffer_length,0);

    BIO_free(bio); // Liberare la memoria del BIO
    return 0; // Invio della chiave pubblica completato con successo
}


// bool checkOverflow(char * input,int max_dim){
//     int input_dim=strlen(input)+1;
//     if (input_dim>max_dim)
//         return true;
//     return false;
// }

