#include "utility.h"
// definizione variabili per Diffie-Hellman
EVP_PKEY * dh_params;      

struct client {
    char *username;
    char *email ;
    unsigned char * pswdHash;
    struct client * next;
};

int main(int argc, char** argv){    
    int listener, new_sd,len;
    int srv_port;
    int ret;
    int addrlen; 
    char buffer[KEY_LENGTH];
    int fdmax; 
    int i;
    struct secret_Params * sessionParam= NULL;
    struct client * users = NULL;
    uint16_t lmsg; 
    struct sockaddr_in my_addr,cl_addr;
    fd_set master;
    fd_set read_fds;

    if (argc > 2){
        printf("Invalid parameters -> program exit\n");
        exit(1);
    }
    
    if (argc == 1)
        srv_port = 4242;            // server in ascolto sulla porta 4242
    else
        srv_port = atoi(argv[1]);   // server in ascolto sulla porta passata come parametro al comando
        
    listener = socket(AF_INET, SOCK_STREAM, 0); // creazione socket di ascolto 
    if (listener == -1){
        printf("Error creating the listening socket\n");
        exit(1);
    }

    /* Creazione indirizzo di bind */
    memset(&my_addr, 0, sizeof(my_addr)); 
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(srv_port);
    //my_addr.sin_addr.s_addr = INADDR_ANY;
    inet_pton(AF_INET, "127.0.0.1", &my_addr.sin_addr);

    ret = bind(listener, (struct sockaddr*)&my_addr, sizeof(my_addr)); // associazione socket ip
    if (ret == -1){
        printf("bind() error\n");
        exit(1);
    }
    ret = listen(listener, 10); //server in ascolto su socket listener con coda di max 10 client
    if (ret == -1){
        printf("listen() error\n");
        exit(1);
    }

    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(0, &master);             // aggiungo il descrittore 0 (stdin) al set dei socket monitorati
    FD_SET(listener, &master);      // aggiungo il listener al set dei socket monitorati
    fdmax = listener;               // il maggiore dei descrittori ora è il listener
    addrlen = sizeof(cl_addr);

    keys_generation("server");      // generazione delle chiavi RSA pubblica e privata usate per la firma digitale

    DH_parameter_generation();      
    
    // Recover p and g
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());

    while (1){
        read_fds = master;
        ret = select(fdmax+1, &read_fds, NULL, NULL, NULL);
        if (ret == -1){
            printf("select() error\n");
            continue;
        }
        
        for (i = 0; i <= fdmax; i++){
            if (FD_ISSET(i, &read_fds)){
                if(i == listener){
                    new_sd = accept(listener, (struct sockaddr *) &cl_addr, &addrlen);
                    if (new_sd == -1){
                        printf("Error creating connection with the client\n");
                        continue;
                    }
                    FD_SET(new_sd, &master);
                    if(new_sd > fdmax){ fdmax = new_sd; } 
                }else{
                    if(recvMsg(buffer,i)==-1){
                        close(i);
                        FD_CLR(i, &master);
                        continue;
                    }
                
                    if(strcmp(buffer,"HANDSHAKE")==0){
                        printf("Handshake start...\n");
                        srand(time(NULL));
                        EVP_PKEY * priv_key;
                        EVP_PKEY_CTX * DH_ctx; //--> Context for Diffi Hellman
                        EVP_PKEY* DH_keys; // --> Contains both 'a' and 'G^a'
                        // ricezione chiave pubblica del client (certificato)
                        long size = recvMsg(buffer,i);
                        if(size==-1){
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        insertFile(buffer, size, i);
                        printf("Client certificate received \n");

                        // Invio chiave pubblica server   
                        
                        // Genearation of public/private pair
                        DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
                        priv_key = retrieve_privkey("server");
                        DH_keys = NULL;
                        DH_PubPriv(dh_params, &DH_keys, DH_ctx);   // generazione parametro privato b e pubblic g^b
                        printf("Private/public pair for DH generated\n");
                        EVP_PKEY_CTX_free(DH_ctx);
                        unsigned char* signature;
                        signature = malloc(EVP_PKEY_size(priv_key));
                        int signature_length=Digital_Signature(priv_key, DH_keys, signature);

                        EVP_PKEY * DH_client_keys;
                        EVP_PKEY * C_pub_key=retrieve_pubkey("server",i);
                        
                        unsigned char * client_signature = malloc(EVP_PKEY_size(C_pub_key));
                        long client_sign_len;
                        unsigned char * DH_pub_client = malloc(2*KEY_LENGTH);
                        size=recvMsg(DH_pub_client,i);
                        if(size==-1){
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("g^a received correctly\n");

                        client_sign_len=recvMsg(client_signature,i);
                        if(client_sign_len==-1){
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Signature on g^a received correctly\n");
                        
                        BIO *bio = BIO_new_mem_buf(DH_pub_client, size);
                        if (!bio) {
                            // Errore nella creazione del BIO
                             close(i);
                             FD_CLR(i, &master);
                             continue;
                        }
                        // Lettura della chiave pubblica dal BIO
                        DH_client_keys= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
                        if (!DH_client_keys) {
                            // Errore nella lettura della chiave pubblica dal BIO
                            BIO_free(bio); // Liberare la memoria del BIO
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        // Liberare la memoria del BIO
                        BIO_free(bio);

                        ret=Verify_Signature(DH_client_keys,C_pub_key,client_signature,client_sign_len);
                        if(ret!=1){
                            printf("Signature Verification on g^a Error \n");
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Signature Verification on g^a Success \n");

                        if (!send_public_key(i,DH_keys)){
                            printf("Error sending g^b\n");
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("g^b sent correctly\n");

                        ret = sendMsg(signature,i,signature_length);
                        if (ret == -1){
                            printf("Send signature on g^b error\n");
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Signature on g^b sent correctly\n");
                        
                        //DH_client_keys contains g^a
                        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(DH_keys, NULL);
                        EVP_PKEY_derive_init(ctx_drv);
                        EVP_PKEY_derive_set_peer(ctx_drv, DH_client_keys);
                        unsigned char* secret;
                        size_t secretlen;
                        //DERIVING SHARED SECRET LENGTH
                        EVP_PKEY_derive(ctx_drv, NULL, &secretlen);
                        //DERIVING SHARED SECRET
                        secret = (unsigned char*)malloc(secretlen);
                        EVP_PKEY_derive(ctx_drv, secret, &secretlen);
                        EVP_PKEY_CTX_free(ctx_drv);

                        char nonce_buf[11];
                        int nonce=rand();
                        sprintf(nonce_buf,"%d",nonce);

                        //generate first session key-->hash(secret)
                        unsigned char* digest;
                        int digestlen;
                        digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

                        digestlen=Hash(digest,secret,secretlen);
                        
                        //send nonce
                        ret = sendMsg(nonce_buf,i,strlen(nonce_buf)+1);
                        if (ret == -1){
                            printf("Send nonce error\n");
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Nonce sent correctly\n");

                        //fulfil the data structure for the session parameters of the user
                        struct secret_Params * temp;
                        temp=malloc(sizeof( struct secret_Params));
                        temp->nonce = strdup(nonce_buf);
                        temp->sd=i;
                        temp->session_key1 = digest;
                        temp->session_key2 = NULL;
                        temp->is_logged = false;
                        temp->seq_nonce=nonce;
                        if(sessionParam==NULL){
                            temp->next=NULL;
                            sessionParam =temp;
                        }else {
                            temp->next=sessionParam;
                            sessionParam=temp;
                        }

                        //Eliminare b a g^b g^a g^ab
                        free(secret);
                        EVP_PKEY_free(DH_keys);
                        EVP_PKEY_free(DH_client_keys);
                        EVP_PKEY_free(priv_key);
                        free(signature);
                        free(client_signature); 

                        printf("Handshake completed.\n");
                        strcpy(buffer,"");
                    }else if(strcmp(buffer,"REGISTRATION")==0){
                         
                        printf("Registration start...\n");
                        EVP_PKEY * C_pub_key=retrieve_pubkey("server",i);
                        unsigned char *ciphertext = (unsigned char*)malloc(MAX_LENGTH+US_LENGTH+67 + 16); //--> Credenziali cifrate
                        int cipherlen = recvMsg(ciphertext,i);
                        if(cipherlen==-1){
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Ciphertext of client's credentials received correctly\n");
                        
                        unsigned char * client_signature = malloc(EVP_PKEY_size(C_pub_key));
                        long client_sign_len=recvMsg(client_signature,i);
                        if(client_sign_len==-1){
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Signature on ciphertext received correctly\n");

                        ret=Verify_Signature_Msg(ciphertext,C_pub_key,client_signature,client_sign_len);
                        if(ret!=1){
                            printf("Signature Verification on received ciphertext Error \n");
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Signature Verification on received ciphertext Success \n");

                        //Decifro le credenziali
                        unsigned char * session_key1 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256())); 
                        //recupero session key
                        struct secret_Params * temp=sessionParam;
                        while(temp != NULL){
                            if(temp->sd==i){
                                session_key1=temp->session_key1;
                                break;
                            }
                            temp=temp->next;
                        }
                        if(temp==NULL){
                            printf("Session key Not Found \n");
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        unsigned char * plaintext=malloc(MAX_LENGTH + US_LENGTH +67);
                        int outlen;
                        int plainlen;
                        EVP_CIPHER_CTX* ctx;
                        ctx = EVP_CIPHER_CTX_new();
                        EVP_DecryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
                        EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
                        plainlen = outlen;
                        ret = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
                        if(ret == 0){
                            printf("Decryption Error \n");
                        }else{
                         printf("Correct Decryption: username, email, H(password) received\n");
                        }
                        plainlen += outlen;
                        EVP_CIPHER_CTX_free(ctx);
                        
                        
                        char username [US_LENGTH];
                        char email [MAX_LENGTH];
                        unsigned char pswd[65];
                        //parse del plaintext 
                        sscanf(plaintext,"%s %s",username,email);
                        int start=strlen(username)+strlen(email)+2;
                        int end =start+64;
                        for(int i=start;i<end;i++){
                            pswd[i-start]=plaintext[i];
                        }     
                        pswd[64]='\0';
                        struct client * app=users;  
                        while(app!=NULL){
                            if(strcmp(app->username,username)==0 || strcmp(app->email,email)==0){
                                printf("Registration Failed \nCredential already used \n");
                                char msg[]="FAILED\0";
                                ret = sendMsg(msg,i,strlen(msg));
                                if (ret == -1){
                                    printf("Send Failed message error\n");
                                    close(i);
                                    FD_CLR(i, &master);
                                    continue;
                                }
                                break;
                            }
                            app=app->next;
                        }
                       
                        if(app == NULL){
                            char msg[]="REGOK\0";
                            ret = sendMsg(msg,i,strlen(msg));
                            if (ret == -1){
                                printf("Send RegOK message error\n");
                                close(i);
                                FD_CLR(i, &master);
                                continue;
                            }
                            
                            char path [US_LENGTH+15];
                            sprintf(path,"CHALLENGE_%s.txt",username);
                            FILE * file=fopen(path,"w");
                            int challenge=rand();
                            fwrite(&challenge,sizeof(int),1,file);
                            fclose(file);
                            char chall_recv[11];
                            int chall_resp;
                            if(recvMsg(chall_recv,i)==-1){
                                close(i);
                                FD_CLR(i, &master);
                            }
                            printf("Challenge response received correctly\n");
                            
                            sscanf(chall_recv,"%d",&chall_resp);
                            if(challenge == chall_resp){
                                printf("Challenge completed\n");
                                char msg[]="CHALOK\0";
                                ret = sendMsg(msg,i,strlen(msg));
                                if (ret == -1){
                                    printf("Send ChalOK message error\n");
                                    close(i);
                                    FD_CLR(i, &master);
                                    continue;
                                }
                                app=malloc(sizeof(struct client));
                                app->username = strdup(username);         
                                app->pswdHash = strdup(pswd);     
                                app->email = strdup(email);
                                
                                if(users == NULL){
                                    app->next=NULL;
                                }else{
                                    app->next=users;
                                }
                                users=app;
                                }
                            remove(path);  
                        }
                        
                        if(removeSessionParam(i,&sessionParam))
                            printf("Parametri deallocati\n");
                        else 
                            printf("Parametri non trovati\n");
                        printf("User registration completed.\n");
                        
                        strcpy(buffer,"");
                    }else if(strcmp(buffer,"LOGIN")==0){
                        printf("Starting Login Phase \n");
                        unsigned char * session_key1=(unsigned char*)malloc(EVP_MD_size(EVP_sha256())); 
                        unsigned char * ciphertext = (unsigned char*)malloc(US_LENGTH+64*2+2+16); //--> Credenziali cifrate
                        int cipherlen = recvMsg(ciphertext,i);
                        if(cipherlen==-1){
                            close(i);
                            FD_CLR(i, &master);
                            continue;
                        }
                        printf("Ciphertext of client's credentials received correctly\n");
                        struct secret_Params * temp_session=sessionParam;
                        bool login_error=false;
                        while(temp_session!=NULL){
                            if(temp_session->sd==i){
                                session_key1=strdup(temp_session->session_key1);
                                if(temp_session->is_logged){
                                    printf("Already logged\n");
                                    login_error=true;
                                    break;
                                }
                                break;
                            }
                            temp_session=temp_session->next;
                        }
                        if(login_error){
                            strcpy(buffer,"");
                            continue;
                        }
                        unsigned char * plaintext=malloc(US_LENGTH +64*2+2);
                        int outlen;
                        int plainlen;
                        EVP_CIPHER_CTX* ctx;
                        ctx = EVP_CIPHER_CTX_new();
                        EVP_DecryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
                        EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
                        plainlen = outlen;
                        ret = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
                        plainlen += outlen;
                        if(ret == 0){
                            printf("Decryption Error \n");
                        }else{
                         printf("Correct Decryption: username, H(password), HMAC\n");
                        }
                        
                        EVP_CIPHER_CTX_free(ctx);
                        
                        char username [US_LENGTH];
                        char Hpswd [65];
                        char Hmac [65];
                        
                        sscanf(plaintext,"%s",username);
                        
                        int start=strlen(username)+1;
                        int end =start+128;
                        for(int i=start;i<end;i++){
                            if(i<(64+start))
                                Hpswd[i-start]=plaintext[i];
                            else 
                                Hmac[i-64-start]=plaintext[i];
                        }     
                        Hmac[64]='\0';
                        Hpswd[64]='\0';
                        
                        unsigned char *session_key2 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                        struct client * temp_client=users;
                        int key2_size;
                        while(temp_client!=NULL){
                            if(strcmp(temp_client->username,username)==0){
                                printf("Found User\n");
                                if(CRYPTO_memcmp(temp_client->pswdHash, Hpswd,EVP_MD_size(EVP_sha256())) == 0){
                                    printf("Password Corrisponding\n");
                                    char key2[75];
                                    sprintf(key2,"%s%s",Hpswd,temp_session->nonce);
                                    key2_size=Hash(session_key2,key2,strlen(key2));
                                    temp_session->session_key2=session_key2;
                                    break;
                                }
                            }
                            temp_client=temp_client->next;
                        }
                        if(temp_client ==NULL){
                            printf("User not found or incorrect password\n");
                            close(i);
                            FD_CLR(i,&master);
                            continue;
                        }
                        unsigned char HP_buf[64+US_LENGTH+1]; 
                        sprintf(HP_buf,"%s %s",username,Hpswd);
                        char mcBuf[33];
                        int mac_len;
                        HMAC(EVP_sha256(), session_key2, key2_size, HP_buf,(start+64), mcBuf, &mac_len);
                        mcBuf[32]='\0';
                        unsigned char exHmac[64];
                        for (int i = 0; i < 32; ++i) {
                            sprintf(exHmac+ (i * 2),"%02X", mcBuf[i]);
                        }
                        if(CRYPTO_memcmp(Hmac, exHmac,64) != 0){
                            printf("Mac Verification failed\n");
                            close(i);
                            FD_CLR(i,&master);
                            continue;
                        }
                        printf("Mac Verification completed\n");
                        sendMsg("LOGINOK",i,8);
                        temp_session->is_logged=true;
                        strcpy(buffer,"");
                    }                
                }
            }
        }
    }
    return 0;
}