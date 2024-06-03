#include "utility.h"
// definizione variabili per Diffie-Hellman
EVP_PKEY * dh_params;      

struct client {
    char *username;
    char *email ;
    unsigned char * pswdHash;
    struct client * next;
};

struct post{
    int mid;
    char title[20];
    char author[20];
    char body[500];
    struct post *next; 
};

int main(int argc, char** argv){    
    int listener, new_sd,len;
    int srv_port;
    int ret;
    int addrlen; 
    char buffer[16+64+MSG_LENGTH];
    struct post * board= NULL;
    int message_id = 0;
    int buffer_size;
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
                    buffer_size=recvMsg(buffer,i);
                    if(buffer_size==-1){
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
                        free(plaintext);
                        free(ciphertext);
                    }
                    else{
                        //Check if logged
                        struct secret_Params * temp_session = sessionParam;
                        bool ret=false;
                        while(temp_session!=NULL){
                            if(temp_session->sd==i){
                                if(temp_session->is_logged)
                                    ret=true;
                                    break;
                            }
                            temp_session=temp_session->next;
                        }
                        if(!ret){
                            continue;
                        }
                        char msg[MSG_LENGTH];
                        int req_nonce=atoi(temp_session->nonce);
                        printf("Prima di message receipts\n");
                        int res=messageReceipts(msg,buffer,buffer_size,temp_session->session_key1,temp_session->session_key2,req_nonce);
                        if(res==0){
                            req_nonce++;
                            sprintf(temp_session->nonce,"%d",req_nonce);
                        }else{
                            continue;
                        }
                        //msg=CMD OPERANDS
                        printf("Msg: %s\n", msg);
                        if(strncmp(msg,"LST",3)==0){
                            // int n;
                            // char number[6];
                            // printf("Ricevuto %s\n",msg);
                            // printf("strlen msg =%ld\n",strlen(msg));
                            // for(int i=3;i<strlen(msg);i++){
                            //     number[i-3]= msg[i];
                            // }
                            // number[strlen(msg)-3]='\0';
                            // sscanf(number,"%d",&n);
                            // printf("number=  %s\nn= %d\n",number,n);
                            // struct post * temp=board;
                            // char messages_list[n*MSG_LENGTH];
                            // for(int i=0;i<n;i++){
                            //     if(temp==NULL)
                            //         break;
                            //     sprintf(messages_list,"%s 
                            //     ")

                            // }

                        }else if(strncmp(msg,"ADD",3)==0){
                            printf("Adding a new message to the BBS...\n");
                            char title[20];
                            char author[20];
                            char body[500];
                            char cmd[4];
                            sscanf(msg, "%s", cmd);
                            int i = 4;
                            int j = 0;
                            do{
                                title[j++] = msg[i++]; 
                            }while(msg[i]!='_');
                            title[j]='\0';
                            j = 0;
                            i++;
                            do{
                                author[j++] = msg[i++]; 
                            }while(msg[i]!='_');
                            author[j] = '\0';
                            j = 0;
                            i++;
                            for(i; i < strlen(msg); i++){
                                body[j++] = msg[i]; 
                            }
                            body[j] = '\0';
                            // inserisco il messaggio in bacheca
                            struct post * temp_post;    // DA METTERE FUORI
                            temp_post=malloc(sizeof( struct post));
                            temp_post->mid = message_id++;
                            strcpy(temp_post->title,title);
                            strcpy(temp_post->author,author);
                            strcpy(temp_post->body,body);
                            if(board==NULL){
                                temp_post->next=NULL;
                                board =temp_post;
                            }else {
                                temp_post->next=board;
                                board=temp_post;
                            }
                            printf("New message added correctly!\nHere all the messages in the BBS:\n");
                            printf("--------------------------------\n");
                            temp_post = board;
                            while(temp_post!=NULL){
                                printf("Mid: %d\n",temp_post->mid);
                                printf("Title: %s\n",temp_post->title);
                                printf("Author: %s\n",temp_post->author);
                                printf("Body: %s\n",temp_post->body);
                                printf("--------------------------------\n");
                                temp_post = temp_post->next;
                            }
                        }else if(strncmp(msg,"GET",3)==0){
                            printf("sono entrato %s\n", msg);
                            char cmd[4];
                            int mid;
                            int returns;
                            char get_buffer[550];
                            sscanf(msg, "%s %d", cmd,&mid);

                            struct post * temp_post=board;
                            while(temp_post!=NULL){
                                if(temp_post->mid == mid){
                                    printf("Found MSG\n");
                                    printf("title %s, author %s , body %s\n",temp_post->title, temp_post->author, temp_post->body);
                                    printf("title_len %d, author %d , body %d\n",strlen(temp_post->title), strlen(temp_post->author), strlen(temp_post->body));

                                    sprintf(get_buffer, "%d_%s_%s_%s",temp_post->mid, temp_post->title, temp_post->author, temp_post->body);
                                    get_buffer[sizeof(mid)+543] = '\0';
                                    printf("get buffer %s \n", get_buffer);
                                    returns = messageDeliver(get_buffer,temp_session->session_key1,temp_session->session_key2,i,req_nonce);

                                        printf("sono entrato \n");
                                        req_nonce++;
                                        sprintf(temp_session->nonce,"%d",req_nonce);

                                    if (returns == -1){
                                        close(i);
                                        FD_CLR(i, &master);
                                        continue;
                                    }
                                    break;
                                    
                                }
                                temp_post=temp_post->next;
                            }



                        }else if(strncmp(msg,"OUT",3)==0){
                            temp_session->is_logged=false;
                        }else{
                            //errore
                        }

                        strcpy(buffer,"");
                    }

                }
            }
        }
    }
    return 0;
}