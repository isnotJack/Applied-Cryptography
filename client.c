/*gestire la connessione come una funzione, date le richiesti di login e logout*/
#include "utility.h"

//GLOBAL FOR SCOPE
EVP_PKEY * pubkey;         // per contenere la chiave pubblica da inviare al server
EVP_PKEY * serverKey;      // per la chiave pubblica del server (utile per verificare la sua firma)
// Parametri Diffie-Hellman
EVP_PKEY * dh_params;

int start(){
    int choice;
    
    printf("Select one of the following options:\n");
    printf("[1] Registration\n");
    printf("[2] Login\n");
    printf("[3] Exit\n");
    
    while(1){
        printf("> ");
        scanf("%d", &choice);
        while(getchar() !='\n');
        if(choice != 1 && choice != 2 && choice != 3){
            printf("Invalid choice, try again.\n");
        }else{
            return choice;
        }
    }
}

void handshake(char * username,int sd,unsigned char* session_key1,int digestlen,char * nonce_buf){
    EVP_PKEY_CTX * DH_ctx;
    EVP_PKEY* DH_keys;
    EVP_PKEY * priv_key;        // per la chiave privata usata per firmare
    int ret;

    pubkey = retrieve_pubkey(username,0);

    printf("Handshake start...\n");
    ret = sendMsg("HANDSHAKE",sd,10);
    if (ret == -1){
        printf("Send Handshake message error \n");
        close(sd);
        exit;
    }
    if (!send_public_key(sd, pubkey)){            // invio al server della chiave pubblica RSA
        printf("Error sending RSA public key\n");
        close(sd);
        exit;
    }
    printf("RSA public key sent correctly\n");

    //printf("Dopo send public key\n");

    //Chiave pubblica server letta da file del server "keys_server" (BARBINO)
    serverKey = retrieve_pubkey("server",-1);

    // Genearation of public/private pair
    DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    DH_keys = NULL;
    DH_PubPriv(dh_params,&DH_keys,DH_ctx);
    printf("Private/public pair for DH generated\n");

    priv_key = retrieve_privkey(username);   // chiave per poter firmare il parametro pubblico di DH
    unsigned char * signature;
    signature = malloc(EVP_PKEY_size(priv_key));
    int signature_length=Digital_Signature(priv_key,DH_keys,signature);

    if (!send_public_key(sd,DH_keys)){
        printf("Error sending g^a\n");
        close(sd);
        exit;
    }
    printf("g^a sent correctly\n");

    ret = sendMsg(signature,sd,signature_length);
    if (ret == -1){
        printf("Send signature on g^a error \n");
        close(sd);
        exit;
    }
    printf("Signature on g^a sent correctly\n");

    /////////RICEVO DAL SERVER ///////
    EVP_PKEY * DH_server_keys;
    
    unsigned char * server_signature = malloc(EVP_PKEY_size(serverKey));
    long server_sign_len;
    unsigned char * DH_pub_server = malloc(2*KEY_LENGTH);
    int size=recvMsg(DH_pub_server,sd);
    if(size==-1){
        printf("Receive of g^b error \n");
        close(sd);
        exit;
    }
    printf("g^b received correctly\n");

    server_sign_len=recvMsg(server_signature,sd);
     if(server_sign_len==-1){
        printf("Receive of signature on g^b error \n");
        close(sd);
        exit;
    }
    printf("Signature on g^b received correctly\n");


    BIO *bio = BIO_new_mem_buf(DH_pub_server, size);
     if (!bio) {
        // Errore nella creazione del BIO
            close(sd);
            exit(1);
    }
    // Lettura della chiave pubblica dal BIO
    DH_server_keys= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!DH_server_keys) {
        // Errore nella lettura della chiave pubblica dal BIO
        BIO_free(bio); // Liberare la memoria del BIO
        close(sd);
        exit(1);
    }

    BIO_free(bio);
    ret = Verify_Signature(DH_server_keys,serverKey,server_signature,server_sign_len);
    if(ret!=1){
        printf("Signature Verification on g^b Error \n");
        close(sd);
        exit(1);
    }
    printf("Signature Verification on g^b Success \n");

    //DH_server_keys contains g^b
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(DH_keys, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, DH_server_keys);
    unsigned char* secret;
    size_t secretlen;
    //DERIVING SHARED SECRET LENGTH
    EVP_PKEY_derive(ctx_drv, NULL, &secretlen);
    //DERIVING SHARED SECRET
    secret = (unsigned char*)malloc(secretlen); // --> G^ab
    EVP_PKEY_derive(ctx_drv, secret, &secretlen);
    EVP_PKEY_CTX_free(ctx_drv);

    //generate first session key-->hash(secret)
    digestlen = Hash(session_key1, secret, secretlen);

    // ricezione del nonce che verrà usato per generare l'altra chiave di sessione
    // utile solo quando l'handshake è seguito dal login
    if(recvMsg(nonce_buf,sd)==-1){
        printf("Error receiving nonce\n");
        close(sd);
        exit(1);
    }
    printf("Nonce received correctly\n");

    //Eliminazione a g^a g^b g^ab
    free(secret);
    free(DH_keys);
    free(DH_server_keys);
    free(priv_key);
}

void registration(char email[],char username[],char password[],int sd){
    int ret;

    //inserire credenziali
    printf("Insert the following parameters\n");
    do{
        printf("Email: ");
        fgets(email, MAX_LENGTH, stdin); 
        email[strcspn(email, "\n")] = '\0';
        fflush(stdin);
    }while(!checkInput(email));

    do{
        printf("Username: "); 
        fgets(username, US_LENGTH, stdin); 
        username[strcspn(username, "\n")] = '\0';
        fflush(stdin);
    }while(!checkInput(username));

    do{
        printf("Password: ");  
        fgets(password, MAX_LENGTH, stdin); 
        password[strcspn(password, "\n")] = '\0';
        fflush(stdin);
    }while(!checkInput(password));

    
    keys_generation(username);
    unsigned char * session_key1 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    int digestlen;
    char nonce_buf[11];
    handshake(username, sd,session_key1,digestlen,nonce_buf);     // esecuzione protocollo di handshake
    printf("Handshake completed.\n");

    printf("Registration start...\n");
    // mandare credenziali cifrate e con firma
    unsigned char * pswdHash;
    pswdHash = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    int pswdHashLen=Hash(pswdHash,password,strlen(password));
    unsigned char sendBuffer[MAX_LENGTH +US_LENGTH+256];
    sprintf(sendBuffer,"%s %s %s",username,email,pswdHash);
    
    EVP_PKEY * priv_key=retrieve_privkey(username);
    unsigned char * ciphertext = (unsigned char*)malloc(sizeof(sendBuffer) + 16); //--> Credenziali cifrate
    int cipherlen;
    int outlen;
    //Cifro send buffer con k1
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen,(unsigned char*)sendBuffer, sizeof(sendBuffer));
    cipherlen = outlen;
    EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
    cipherlen += outlen;
    EVP_CIPHER_CTX_free(ctx);

    //firmo send buffer cifrato
    unsigned char * signature=malloc(EVP_PKEY_size(priv_key));
    int signature_length=Digital_Signature_Msg(priv_key,ciphertext,signature);
    
    //invio credenziali cifrate + firma digitale

    ret = sendMsg("REGISTRATION",sd,13);
    if (ret == -1){
        printf("Send Registration error \n");
        close(sd);
        exit;
    }

    ret = sendMsg(ciphertext,sd,cipherlen);
    if (ret == -1){
        printf("Send ciphertext error \n");
        close(sd);
        exit;
    }
    printf("Enc(username, email, H(password)) sent correctly\n");
    
    ret = sendMsg(signature,sd,signature_length);
    if (ret == -1){
        printf("Send ciphertext signature error \n");
        close(sd);
        exit;
    }
    printf("Signature on ciphertext sent correctly\n");

    char temp_buffer[20];
    if(recvMsg(temp_buffer,sd)==-1){
        close(sd);
        return;
    }
    if(strcmp(temp_buffer,"FAILED\0")==0){
        printf("Registration failed: Credential Already Used\n");
    }else{
        char path [US_LENGTH+15];
        sprintf(path,"CHALLENGE_%s.txt",username);
        int challenge;
        FILE * file =fopen(path,"r");
        fread(&challenge,sizeof(int),1,file);
        fclose(file);
        char sendChall[11];
        sprintf(sendChall,"%d",challenge);
        ret = sendMsg(sendChall,sd,strlen(sendChall));
        if (ret == -1){
            printf("Send challenge response error \n");
            close(sd);
            exit;
        }
        printf("Challenge response sent correctly\n");
        if(recvMsg(temp_buffer,sd)==-1){
            close(sd);
            return;
        }
        if(strcmp(temp_buffer,"CHALOK\0")==0)
            printf("Registration Completed.\n");
        else{
            printf("Registration failed : challenge not completed.\n");
        }
    }
}

void help(){
    printf("[1] List(int n): lists the latest n available messages in the BBS");
    printf("\n[2] Get(int msg_id): downloads from the BBS the message specified by msg_id");
    printf("\n[3] Add(String title,String author,String body): adds a message to the BBS\n");
}

void menu_operation(){
    printf("Welcome, to interact insert the name of the functions");
    printf("\n[1] List");
    printf("\n[2] Get");
    printf("\n[3] Add");
    printf("\n[4] Help\n");
}

void menu_registration(){
    printf("Please to interact with the BBS, register to the system");
    printf("\n [email_address] [nickname] [password] ");
}

void menu_login(){
    printf("Please login to the system");
    printf("\n [nickname] [password] ");
}

int main(int argc, char** argv){
    int ret,sd, len;
    uint16_t lmsg;
    int clt_port;
    struct sockaddr_in srv_addr;
    int var=0;
    char email[MAX_LENGTH];
    char username[US_LENGTH];
    char password[MAX_LENGTH];

    if (argc != 2){
        printf("Invalid parameters -> Use ./dev <porta>\n");
        fflush(stdout);
        exit(1);
    }
    
    clt_port = atoi(argv[1]);

    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
    
    var = start();
    sd = socket(AF_INET,SOCK_STREAM,0);
    if (sd == -1){
        printf("Error in the creation of the socket\n");
        exit(1);
    }

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(clt_port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

    ret = connect(sd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret < 0){
        printf("Connection error\n");
        exit(1);
    }

    do{
        if(var == 1){
            registration(email, username, password,sd);
        }else if(var == 2){
            //login(email,username,password);
            //handshake();
        }else if(var == 3){
            //Funzione di exit
            printf("Closing Application\n");
            close(sd);
            return 0;
        }
        var=start();
    } while(1);

    close(sd);

    return 0;
}