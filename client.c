#include "utility.h"

EVP_PKEY * pubkey;         
EVP_PKEY * serverKey;      

EVP_PKEY * dh_params;
int seq_nonce=0;    

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

void handshake(char * username,int sd,unsigned char* session_key1,int key1_len,char * nonce_buf){
    EVP_PKEY_CTX * DH_ctx;
    EVP_PKEY* DH_keys;
    EVP_PKEY * priv_key;        
    int ret;

    pubkey = retrieve_pubkey(username,0);

    printf("Handshake start...\n");
    ret = sendMsg("HANDSHAKE",sd,10);
    if (ret == -1){
        printf(" - Send Handshake message error \n");
        close(sd);
        exit(1);
    }
    char random_buf[11];
    ret = recvMsg(random_buf,sd);
    if (!send_public_key(sd, pubkey)){            // "sending certificate"
        printf(" - Error sending RSA public key\n");
        close(sd);
        exit(1);
    }
    printf(" - RSA public key sent correctly\n");

    // server's public key read read from file
    serverKey = retrieve_pubkey("server",-1);

    // Genearation of public/private pair
    DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    DH_keys = NULL;
    DH_PubPriv(dh_params,&DH_keys,DH_ctx);
    printf(" - Private/public pair for DH generated\n");

    priv_key = retrieve_privkey(username); 
    unsigned char * signature;
    signature = malloc(EVP_PKEY_size(priv_key));
    int signature_length=Digital_Signature(priv_key,DH_keys,signature);

    if (!send_public_key(sd,DH_keys)){
        printf(" - Error sending g^a\n");
        close(sd);
        exit(1);
    }
    printf(" - g^a sent correctly\n");

    ret = sendMsg(signature,sd,signature_length);
    if (ret == -1){
        printf(" - Send signature on g^a error \n");
        close(sd);
        exit(1);
    }
    printf(" - Signature on g^a sent correctly\n");

    EVP_PKEY * DH_server_keys;
    
    unsigned char * server_signature = malloc(EVP_PKEY_size(serverKey));
    long server_sign_len;
    unsigned char * DH_pub_server = malloc(2*KEY_LENGTH);
    int size=recvMsg(DH_pub_server,sd);
    if(size==-1){
        printf(" - Receive of g^b error \n");
        close(sd);
        exit(1);
    }
    printf(" - g^b received correctly\n");

    server_sign_len=recvMsg(server_signature,sd);
     if(server_sign_len==-1){
        printf(" - Receive of signature on g^b error \n");
        close(sd);
        exit(1);
    }
    printf(" - Signature on g^b received correctly\n");


    BIO *bio = BIO_new_mem_buf(DH_pub_server, size);
     if (!bio) {
        close(sd);
        exit(1);
    }
    
    DH_server_keys= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!DH_server_keys) {
        BIO_free(bio); 
        close(sd);
        exit(1);
    }

    BIO_free(bio);
    ret = Verify_Signature(DH_server_keys,serverKey,server_signature,server_sign_len);
    if(ret!=1){
        printf(" - Signature Verification on g^b Error \n");
        close(sd);
        exit(1);
    }
    printf(" - Signature Verification on g^b Success \n");

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
    key1_len = Hash(session_key1, secret, secretlen);

    // nonce used to generate SessionKey2 when handshake is followed by login phase
    if(recvMsg(nonce_buf,sd)==-1){
        printf(" - Error receiving nonce\n");
        close(sd);
        exit(1);
    }
    printf(" - Nonce received correctly\n");

    //Delete a g^ab
    free(secret);
    EVP_PKEY_free(DH_keys);
    EVP_PKEY_free(DH_server_keys);
    EVP_PKEY_free(priv_key);
    printf("Handshake completed.\n");
}

void registration(char email[],char username[],char password[],int sd){
    int ret;
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
    int key1_len;
    char nonce_buf[11];
    handshake(username, sd,session_key1,key1_len,nonce_buf);  
    

    printf("Registration start...\n");

    unsigned char * pswdHash;
    pswdHash = (unsigned char*)malloc(33);
    int pswdHashLen=Hash(pswdHash,password,strlen(password));
    pswdHash[32]='\0';
    unsigned char * hash_buf=(unsigned char*)malloc(65);
    for (int i = 0; i < pswdHashLen; ++i) {
        sprintf(hash_buf+ (i * 2),"%02X", pswdHash[i]);
    }
    hash_buf[64]='\0';
    unsigned char sendBuffer[MAX_LENGTH +US_LENGTH+67];
    sprintf(sendBuffer,"%s %s %s",username,email,hash_buf);
    
    EVP_PKEY * priv_key=retrieve_privkey(username);
    unsigned char * ciphertext = (unsigned char*)malloc(sizeof(sendBuffer) + 16); 
    memset(ciphertext,0,(sizeof(sendBuffer) + 16));
    int cipherlen;
    int outlen;
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen,(unsigned char*)sendBuffer, sizeof(sendBuffer));
    cipherlen = outlen;
    EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
    cipherlen += outlen;
    EVP_CIPHER_CTX_free(ctx);
    
    unsigned char * signature=malloc(EVP_PKEY_size(priv_key));
    int signature_length=Digital_Signature_Msg(priv_key,ciphertext,signature);

    ret = sendMsg("REGISTRATION",sd,13);
    if (ret == -1){
        printf(" - Send Registration message error \n");
        close(sd);
        exit(1);
    }

    ret = sendMsg(ciphertext,sd,cipherlen);
    if (ret == -1){
        printf(" - Send ciphertext error \n");
        close(sd);
        exit(1);
    }
    printf(" - Enc(username, email, H(password)) sent correctly\n");
    
    ret = sendMsg(signature,sd,signature_length);
    if (ret == -1){
        printf(" - Send ciphertext signature error \n");
        close(sd);
        exit(1);
    }
    printf(" - Signature on ciphertext sent correctly\n");

    char temp_buffer[20];
    memset(temp_buffer,0,20);
    if(recvMsg(temp_buffer,sd)==-1){
        close(sd);
        exit(1);
    }
    if(strcmp(temp_buffer,"FAILED\0")==0){
        printf(" - Registration failed: Credential Already Used\n");
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
            printf(" - Send challenge response error \n");
            close(sd);
            exit(1);
        }
        printf(" - Challenge response sent correctly\n");
        if(recvMsg(temp_buffer,sd)==-1){
            close(sd);
            exit(1);
        }
        if(strcmp(temp_buffer,"CHALOK\0")==0)
            printf("Registration Completed.\n");
        else{
            printf("Registration failed: challenge not completed.\n");
        }
    }
}

void login(char username[],char password[]){
    int ret;

    printf("Insert the following parameters\n");
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
}

void help(){
    printf("[1] List(int n): lists the latest n available messages in the BBS");
    printf("\n[2] Get(int msg_id): downloads from the BBS the message specified by msg_id");
    printf("\n[3] Add(String title,String author,String body): adds a message to the BBS\n");
}

void menu_operation(){
    printf("Welcome, to interact insert the number of the function:");
    printf("\n[1] List");
    printf("\n[2] Get");
    printf("\n[3] Add");
    printf("\n[4] Help");
    printf("\n[5] Logout\n");
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
    unsigned char *session_key1 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    unsigned char *session_key2 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    int key1_len;
    char nonce_buf[11];
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
            login(username,password);
            handshake(username, sd,session_key1,key1_len,nonce_buf);
            printf("Login start...\n");
            unsigned char * pswd_Hash= (unsigned char*)malloc(33);
            int pswd_size=Hash(pswd_Hash,password,strlen(password));
            unsigned char * hash_buf=(unsigned char*)malloc(65);
            pswd_Hash[32]='\0';
            for (int i = 0; i < pswd_size; ++i) {
                sprintf(hash_buf+ (i * 2),"%02X", pswd_Hash[i]);
            }
            char key2[75];
            sprintf(key2,"%s%s",hash_buf,nonce_buf);
            int key2_size=Hash(session_key2,key2,strlen(key2));
            // Session key2 inizialized
            char HP_buf[64+US_LENGTH+1]; 
            sprintf(HP_buf,"%s %s",username,hash_buf);
            int outlen;
            char mcBuf[32];
            HMAC(EVP_sha256(), session_key2, key2_size, HP_buf,(strlen(username)+65), mcBuf, &outlen); 
            //Encryption of Us, PswdHas, HMAC
            unsigned char exHmac[64];
            for (int i = 0; i < 32; ++i) {
                sprintf(exHmac+ (i * 2),"%02X", mcBuf[i]);
            }
            printf(" - HMAC(username|Hpassword) computed");
            char plaintext[64*2+US_LENGTH+2];
            sprintf(plaintext,"%s %s%s",username,hash_buf,exHmac);
            plaintext[strlen(username)+1+128]='\0';
            unsigned char * ciphertext = (unsigned char*)malloc(sizeof(plaintext) + 16);
            memset(ciphertext,0,sizeof(plaintext) + 16);
            int cipherlen;
            EVP_CIPHER_CTX* ctx;
            ctx = EVP_CIPHER_CTX_new();
            /* Encryption (initialization + single update + finalization */
            EVP_EncryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
            EVP_EncryptUpdate(ctx, ciphertext, &outlen,(unsigned char*)plaintext, sizeof(plaintext));
            cipherlen = outlen;
            ret=EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
            if(ret == 0){
                printf(" - Encryption Error \n");
                close(sd);
                exit(1);
            }
            cipherlen += outlen;
            /* Context deallocation */
            EVP_CIPHER_CTX_free(ctx);
            printf(" - Enc(username|H(password)|HMAC) computed\n");
            sendMsg("LOGIN",sd,6);
            sendMsg(ciphertext,sd,cipherlen);
            if (ret == -1){
                printf(" - Send ciphertext error \n");
                close(sd);
                exit(1);
            }
            printf(" - Enc(username|H(password)|HMAC) sent correctly\n");
            char recvBuf[10];
            if(recvMsg(recvBuf,sd)==-1){
                printf(" - Login Failed\n");
                close(sd);
                exit(1);
            }
            if(strcmp(recvBuf,"LOGINOK")==0){
                printf("Login successfully completed\n");
                seq_nonce=atoi(nonce_buf);
                
                while (1){
                    int choice = 0;
                    menu_operation();
                    if (scanf("%d",&choice)!=1){
                        while (getchar() != '\n');
                        continue;
                    }
                    
                    int n = 0;
                    if(choice == 1){
                        char list_buffer[10];
                        printf("Insert the number of latest messages to see:\n");
                        if (scanf("%d",&n) == 0){
                            printf("Invalid input\n");
                            while (getchar() != '\n');
                            continue;
                        }
                        sprintf(list_buffer,"LST %d",n);
                        messageDeliver(list_buffer,session_key1,session_key2,sd,seq_nonce);
                        seq_nonce++;
                        char cipher[MSG_LENGTH];
                        char message[MSG_LENGTH/2];
                        
                        char *title;
                        char *author;
                        char *body;
                        char * mid;
                        while (1)
                        {
                            int cipherlen=recvMsg(cipher,sd);
                            if(cipherlen==-1){
                                printf("Error in list receiving\n");
                                break;
                            }
                            ret=messageReceipts(message,cipher,cipherlen,session_key1,session_key2,seq_nonce);
                            if(ret!=0)
                                break;
                            seq_nonce++;
                            if(strncmp(message,"END",3)==0)
                                break;
                            mid = strtok(message, "_");
                            author = strtok(NULL, "_");
                            title = strtok(NULL, "_");
                            body = strtok(NULL, "_");
                            
                            
                            printf("Mid: %s\nAuthor: %s\nTitle: %s\nBody: %s\n",mid,author,title,body);
                            printf("/---------------------------------------------------------------/\n");
                        }

                    }else if(choice == 2){
                        int k;
                        char choice_buffer[10];
                        char path[100];
                        char buffer[550];
                        char msg[550];
                        int buffer_size;

                        char *part1;
                        char *part2;
                        char *part3;
                        char *part4;

                        printf("Insert the mid to download the message:\n");
                        if (scanf("%d",&k) == 0){
                            printf("Invalid input\n");
                            while (getchar() != '\n');
                            continue;
                        }

                        sprintf(choice_buffer,"GET %d",k);
                        printf("Downloading the specified message from the BBS...\n");

                        messageDeliver(choice_buffer,session_key1,session_key2,sd,seq_nonce);
                            seq_nonce++;


                        buffer_size=recvMsg(buffer,sd);
                        int res=messageReceipts(msg,buffer,buffer_size,session_key1,session_key2,seq_nonce);
                            seq_nonce++;

                        if (strcmp(msg,"NOMID") == 0){
                            printf("Message ID not found.\n");
                            continue;
                        }
         
                        part1 = strtok(msg, "_");
                        part2 = strtok(NULL, "_");
                        part3 = strtok(NULL, "_");
                        part4 = strtok(NULL, "_");

                        sprintf(path, "./Download/message_%s.txt",part1);
                        
                        FILE* file = fopen(path, "w");
                        if(!file) { 
                            printf("Error opening the file\n");
                            exit(1);
                        }
                        fprintf(file, "Title: %s\n", part2);
                        fprintf(file, "Author: %s\n", part3);
                        fprintf(file, "Body:%s\n", part4);
                        
                        fclose(file);

                        printf("You can find the message in the Download folder on your pc.\n");
                        
                    }else if(choice == 3){
                        char title[20];
                        char body[500];
                        char add_buffer[547];
                        printf("Adding a new message to the BBS...\n");
                        printf("Title:\n");
                        while(getchar() !='\n');
                        fgets(title, sizeof(title), stdin);
                        while(getchar() !='\n');
                        int len = strlen(title);
                        if (len > 0 && title[len - 1] == '\n') {
                            title[len - 1] = '\0';
                        }
                        // author is in "username"
                        
                        printf("Body of the message:\n");
                        fgets(body, sizeof(body), stdin);
                        //while(getchar() !='\n');
                        len = strlen(body);
                        if (len > 0 && body[len - 1] == '\n') {
                            body[len - 1] = '\0';
                        }
                        sprintf(add_buffer, "ADD %s_%s_%s", title, username, body);
                        if (messageDeliver(add_buffer,session_key1,session_key2,sd,seq_nonce) != -1){
                            seq_nonce++;
                        }else{
                            continue;
                        }
                    }else if(choice == 4){
                        help();
                    }else if(choice == 5) {
                        printf("Logout...\n");
                        messageDeliver("OUT",session_key1,session_key2,sd,seq_nonce);
                        break;
                    }
                }
            }else{
                printf("Login failed\n");
            }          
        }else if(var == 3){
            printf("Closing Application\n");
            close(sd);
            return 0;
        }
        var=start();
        strcpy(username,"");
        strcpy(email,"");
        strcpy(password,"");
    } while(1);
    close(sd);
    return 0;
}