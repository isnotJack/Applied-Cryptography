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
#include <malloc.h>
#include <stdio.h>
#include <openssl/hmac.h>

int MAX_LENGTH = 50;
int KEY_LENGTH = 1024;
int PUB_CMD_LENGTH = 129;
int PRIV_CMD_lENGTH = 75;
int US_LENGTH = 20;
int MSG_LENGTH = 2048;
struct secret_Params
{
    int sd;
    unsigned char * session_key1;   // used to encrypt messages
    unsigned char * session_key2;   // used for message authentication
    unsigned char * nonce;
    bool is_logged;
    int seq_nonce;
    struct secret_Params * next;
};


// Utility Functions to send and receive the lenght before the message
bool sendMsg(char * msg, int sd,long len){
    int ret;
    long lmsg;
    lmsg = htonl(len);
    ret = send(sd, (void*) &lmsg, sizeof(uint32_t), 0);
    if (ret != -1)
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

int messageReceipts(char * msg,unsigned char * ciphertext,int cipherlen,unsigned char * session_key1,unsigned char * session_key2,int seq_nonce){
    unsigned char plaintext[64+MSG_LENGTH+11+2];
    int outlen;
    int plainlen;
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
    plainlen = outlen;
    int ret = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
    plainlen += outlen;
    printf("Plaintext %s\n",plaintext);
    if(ret == 0){
        printf("Decryption Error \n");
    }else{
        printf("Correct Decryption: Msg, Nonce, HMAC\n");
    }
    EVP_CIPHER_CTX_free(ctx);
    int recNonce;
    char HP_buf[MSG_LENGTH+12];
    unsigned char recHmac[65];
    unsigned char exmsg[MSG_LENGTH];
    sscanf(plaintext,"%s %d %s",exmsg,&recNonce,recHmac);
    int buffer_len= strlen(exmsg)/2;
    for (int i = 0; i < buffer_len; ++i) {
        sscanf(exmsg + (i * 2), "%2hhx", &msg[i]);
    }
    msg[buffer_len]='\0';
    printf("Messaggio convertito %s\n",msg);
    recHmac[64]='\0';
    sprintf(HP_buf,"%s %d",exmsg,recNonce);
    int HP_buf_len=strlen(HP_buf);
    printf("Hp buf len %d\n",HP_buf_len);
    HP_buf[HP_buf_len]='\0';
    char mcBuf[33];
    int mac_len;
    HMAC(EVP_sha256(), session_key2, 32, HP_buf,HP_buf_len, mcBuf, &mac_len);
    
    mcBuf[32]='\0';
    unsigned char exHmac[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(exHmac+ (i * 2),"%02X", mcBuf[i]);
    }
    exHmac[64]='\0';
    printf("Mac generated %s\nMac received %s\n",exHmac,recHmac);
    printf("nonce %d\n",recNonce);
    if(CRYPTO_memcmp(recHmac, exHmac,64) != 0){
        //GESTIONE ERRORE
        printf("Errore nella mac verification\n");
        return -1;
    }
    printf("Dopo verification\n");
    printf("Seq nonce: %d\n", seq_nonce);
    if(recNonce == seq_nonce)
        return 0;
    return 1;
}

int messageDeliver(char * msg,unsigned char * session_key1,unsigned char * session_key2,int sd,int seq_nonce){
    int outlen;
    int key_size=32;
    int msg_len = strlen(msg);
    char mcBuf[32];
    char exmsg[msg_len*2+1];
    for (int i = 0; i < msg_len; ++i) {
        sprintf(exmsg+ (i * 2),"%02X", msg[i]);
    }
    exmsg[msg_len*2]='\0';
    char HP_buf[msg_len*2+12];
    sprintf(HP_buf,"%s %d",exmsg,seq_nonce);
    printf("strlen(HP_buf): %ld\n",strlen(HP_buf));
    HMAC(EVP_sha256(), session_key2, key_size, HP_buf,(strlen(HP_buf)), mcBuf, &outlen); 
    unsigned char exHmac[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(exHmac+ (i * 2),"%02X", mcBuf[i]);
    }
    exHmac[64]='\0';
    printf("exHmac %s\n",exHmac);
    char plaintext[64 + strlen(HP_buf)+2];
    sprintf(plaintext,"%s %s",HP_buf,exHmac);
    printf("Delivered plaintext %s\n",plaintext);
    unsigned char * ciphertext = (unsigned char*)malloc(sizeof(plaintext) + 16);
    int cipherlen;
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    /* Encryption initialization + single update + finalization */
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen,(unsigned char*)plaintext, sizeof(plaintext));
    cipherlen = outlen;
    int ret=EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
    if(ret == 0){
        printf("Encryption Error \n");
        return -1;
    }else{
    printf("Correct Encryption\n");
    }
    cipherlen += outlen;
    /* Context deallocation */
    EVP_CIPHER_CTX_free(ctx);
    ret=sendMsg(ciphertext,sd,cipherlen);
   if(ret == -1){     
        printf("Send encrypted messagge failed\n");
    }else{
        printf("Send encrypted messagge completed\n");
    }
    return ret;
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


void DH_PubPriv(EVP_PKEY* dh_params, EVP_PKEY ** my_prvkey, EVP_PKEY_CTX * DH_ctx){
    EVP_PKEY_keygen_init(DH_ctx);
    EVP_PKEY_keygen(DH_ctx, my_prvkey); //Generate both 'a' and 'g^a'
}

int Hash(unsigned char * digest, unsigned char *msg ,int msg_len){
    int digestlen;
    EVP_MD_CTX* ctx;
    ctx = EVP_MD_CTX_new();
    /* Hashing initialization + single update + finalization */
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, (unsigned char*)msg, msg_len);
    EVP_DigestFinal(ctx, digest, &digestlen);
    /* Context deallocation */
    EVP_MD_CTX_free(ctx);
    return digestlen;
}


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

// Firma digitale su una chiave
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
    printf("Signature on DH public parameter done \n");
    EVP_MD_CTX_free(ctx);
    BIO_free(bio); // Liberare la memoria del BIO
    return signature_len;
}

// Firma digitale su un messaggio
int Digital_Signature_Msg(EVP_PKEY * priv_key, unsigned char * msg, unsigned char * signature){
    int signature_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    // Ottieni il puntatore al buffer di dati BIO
    EVP_SignUpdate(ctx, (unsigned char*)msg,sizeof(msg));
    EVP_SignFinal(ctx, signature, &signature_len,priv_key);
    printf("Signature on Enc(username, email, H(password)) done \n");
    EVP_MD_CTX_free(ctx);
    return signature_len;
}

int Verify_Signature_Msg(unsigned char * ciphertext,EVP_PKEY * pubkey, unsigned char * signature, int signature_length){
    EVP_MD_CTX* VER_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(VER_ctx, EVP_sha256());
    EVP_VerifyUpdate(VER_ctx, ciphertext, sizeof(ciphertext));
    int ret = EVP_VerifyFinal(VER_ctx, signature,signature_length, pubkey);
    EVP_MD_CTX_free(VER_ctx);
    return ret;
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

 bool removeSessionParam(int i,struct secret_Params ** sessionParam){
    struct secret_Params * del=*sessionParam;
    struct secret_Params * before=NULL;
    while(del!=NULL){
        if(del->sd==i){
            if(before==NULL){
                *sessionParam=del->next;
            }
            else
                before->next=del->next;
            //free(del);
            return true;
        }
        before=del;
        del=del->next;
    }
    return false;
 }


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
    int ret;
    BIO *bio = BIO_new(BIO_s_mem()); // Creazione di un BIO in memoria
    if (!bio)
        return 0; // Errore nella creazione del BIO
 
    // Scrittura della chiave pubblica nel BIO
    if (!PEM_write_bio_PUBKEY(bio, public_key)) {
        BIO_free(bio);  // Liberare la memoria del BIO
        return 0;       // Errore nella scrittura della chiave pubblica nel BIO
    }
 
    // Ottieni il puntatore al buffer di dati BIO
    char *buffer_data;
    long buffer_length = BIO_get_mem_data(bio, &buffer_data);
    ret = sendMsg(buffer_data,socket,buffer_length);
    if (ret == -1)
        return 0;

    // long lmsg=htonl(buffer_length);
    // send(socket, (void*) &lmsg, sizeof(uint32_t), 0);
    // // Invia la chiave pubblica sul socket
    // send(socket,(void *) buffer_data,buffer_length,0);

    BIO_free(bio); // Liberare la memoria del BIO
    return 1; // Invio della chiave pubblica completato con successo
}


// bool checkOverflow(char * input,int max_dim){
//     int input_dim=strlen(input)+1;
//     if (input_dim>max_dim)
//         return true;
//     return false;
// }

