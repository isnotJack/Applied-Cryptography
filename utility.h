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

EVP_PKEY_CTX* DH_ctx;      // context for public key operations
EVP_MD_CTX * MD_ctx;       // context for message digest

// Utility Functions to send and receive the lenght before the message
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

//Generation of P and G for DH 
void DH_parameter_generation(){
    char command[MAX_LENGTH];
    sprintf(command,"openssl dhparam -out dh_param.pem -2 -C 2048");
    system(command);   
}

void DH_retrival(EVP_PKEY* dh_params){
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
}

EVP_PKEY_CTX * DH_PubPriv(EVP_PKEY* dh_params, EVP_PKEY * my_prvkey){
    printf("QUI\n");
    DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    printf("QUI2\n");
    my_prvkey = EVP_PKEY_new();
    printf("QUI3\n");
    EVP_PKEY_keygen_init(DH_ctx);
    EVP_PKEY_keygen(DH_ctx, &my_prvkey); //Generate both 'a' and 'G^a'
    return DH_ctx;
}

void Digital_Signature(EVP_PKEY * priv_key, EVP_PKEY * DH_pubkey){
    char* alg="sha1";
    const EVP_MD* md = EVP_get_digestbyname(alg);
    OpenSSL_add_all_digests();
    MD_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(MD_ctx);
    EVP_SignInit(MD_ctx, md);
    // EVP_SignUpdate(MD_ctx, DH_pubkey, );
    char * sign_buffer;
    unsigned int sign_buffer_size;
    EVP_SignFinal(MD_ctx, sign_buffer, &sign_buffer_size, priv_key);
    printf("La firma e' :%s",sign_buffer);
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
        printf("Error opening the file\n");
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

EVP_PKEY * retrieve_pubkey(char * username){
    /* Read a public key from a PEM file */
    EVP_PKEY * pubkey;
    char path[100];
    if(strcmp(username,"server")==0){
         sprintf(path, "./keys_server/rsa_pubkey_%s.pem",username);
    }else{
        sprintf(path, "./keys_clients/rsa_pubkey_%s.pem",username);
    }
    FILE* file = fopen(path, "r");
    if(!file) { 
        printf("Error opening the file\n");
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
        printf("Error opening the file\n");
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

    // Invia la chiave pubblica sul socket
    if (!sendMsg(buffer_data,socket)) {
        BIO_free(bio); // Liberare la memoria del BIO
        return 1; // Errore nell'invio della chiave pubblica
    }
    BIO_free(bio); // Liberare la memoria del BIO
    return 0; // Invio della chiave pubblica completato con successo
}

// bool checkOverflow(char * input,int max_dim){
//     int input_dim=strlen(input)+1;
//     if (input_dim>max_dim)
//         return true;
//     return false;
// }

