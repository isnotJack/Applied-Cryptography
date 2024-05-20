/*mettere tutto in inglese*/
#include "utility.h"
EVP_PKEY * priv_key;
// definizione variabili per Diffie-Hellman
EVP_PKEY * dh_params;      

struct secret_Params
{
    int sd;
    unsigned char * session_key1;   // used to encrypt messages
    unsigned char * session_key2;   // used for message authentication
    unsigned char * nonce;
    struct secret_Params * next;
};

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
                    recvMsg(buffer,i);
                    

                    if(strcmp(buffer,"HANDSHAKE")==0){
                        srand(time(NULL));
                        EVP_PKEY_CTX * DH_ctx; //--> Context for Diffi Hellman
                        EVP_PKEY* DH_keys; // --> Contains both 'a' and 'G^a'
                        // ricezione chiave pubblica del client (certificato)
                        long size = recvMsg(buffer,i);
                        insertFile(buffer, size, i);
                        printf("Client certificate received \n");

                        // Invio chiave pubblica server   

                        // Genearation of public/private pair
                        DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
                        DH_keys = NULL;
                        DH_PubPriv(dh_params, &DH_keys,DH_ctx);   // generazione parametro privato b e pubblic g^b
                        printf("Private/public pair for DH generated\n");
                        priv_key = retrieve_privkey("server");
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
                        client_sign_len=recvMsg(client_signature,i);
                        
                        BIO *bio = BIO_new_mem_buf(DH_pub_client, size);
                        if (!bio) {
                            // Errore nella creazione del BIO
                             close(i);
                             continue;
                        }
                        // Lettura della chiave pubblica dal BIO
                        DH_client_keys= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
                        if (!DH_client_keys) {
                            // Errore nella lettura della chiave pubblica dal BIO
                            BIO_free(bio); // Liberare la memoria del BIO
                            close(i);
                            continue;
                        }
                        // Liberare la memoria del BIO
                        BIO_free(bio);

                        ret=Verify_Signature(DH_client_keys,C_pub_key,client_signature,client_sign_len);
                        if(ret!=1){
                            printf("Signature Verification Error \n");
                            close(i);
                            continue;
                        }
                        printf("Signature Verification Success \n");
                        send_public_key(i,DH_keys);
                        sendMsg(signature,i,signature_length);
                        
                        
                        //DH_client_keys contains G^a
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
                        sendMsg(nonce_buf,i,strlen(nonce_buf)+1);
                        //fulfill the data structure for the session parameters of the user
                        struct secret_Params * temp;
                        temp=malloc(sizeof( struct secret_Params));
                        temp->nonce = nonce_buf;
                        temp->sd=i;
                        temp->session_key1 = digest; 
                        temp->session_key2 = NULL;
                        if(sessionParam==NULL){
                            sessionParam =temp;
                            sessionParam->next=NULL;
                        }else {
                            temp->next=sessionParam;
                            sessionParam=temp;
                        }

                        //Eliminare b G^b G^ab
                        //Eliminare a G^a G^b G^ab
                        free(secret);
                        EVP_PKEY_free(DH_keys);
                        EVP_PKEY_free(DH_client_keys);
                        EVP_PKEY_free(priv_key);
                        free(signature);
                        free(client_signature); 
                        strcpy(buffer,"");
                    }else if(strcmp(buffer,"REGISTRATION")==0){
                        EVP_PKEY * C_pub_key=retrieve_pubkey("server",i);
                        unsigned char * ciphertext = (unsigned char*)malloc(MAX_LENGTH+US_LENGTH+256 + 16); //--> Credenziali cifrate
                        int cipherlen = recvMsg(ciphertext,i);
                        
                        unsigned char * client_signature = malloc(EVP_PKEY_size(C_pub_key));
                        long client_sign_len=recvMsg(client_signature,i);

                        int ret=Verify_Signature_Msg(ciphertext,C_pub_key,client_signature,client_sign_len);
                        if(ret!=1){
                            printf("Signature Verification Error \n");
                            close(i);
                            continue;
                        }
                        printf("Signature Verification Success \n");

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
                            continue;
                        }
                        unsigned char * plaintext=malloc(MAX_LENGTH + US_LENGTH +256);
                        int outlen;
                        int plainlen;
                        EVP_CIPHER_CTX* ctx;
                        ctx = EVP_CIPHER_CTX_new();
                        EVP_DecryptInit(ctx, EVP_aes_256_ecb(), session_key1, NULL);
                        EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
                        plainlen = outlen;
                        ret = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
                        if(ret == 0){
                            printf("Decrypt Error \n");
                        }else{
                         printf("Correct Decryption\n");
                        }
                        plainlen += outlen;
                        EVP_CIPHER_CTX_free(ctx);
                        
                        char username [US_LENGTH];
                        char email [MAX_LENGTH];
                        unsigned char pswd[256];
                        //parse del plaintext 
                        sscanf(plaintext,"%s %s %s",username,email,pswd);
                       printf("Prima di Ricerca\n");
                        //ricerca
                        struct client * app=users;
                        while(app!=NULL){
                            if(strcmp(app->username,username)==0 || strcmp(app->pswdHash,pswd)==0){
                                printf("Registration Failed \n Credential already used \n");
                                char msg[]="FAILED\0";
                                sendMsg(msg,i,strlen(msg));
                                break;
                            }
                            app=app->next;
                        }
                        printf("Prima di App\n");
                        if(app == NULL){
                            app=malloc(sizeof(struct client));
                            app->pswdHash=pswd;
                            app->username=username;
                            app->email=email;
                            
                            if(users == NULL){
                                app->next=NULL;
                            }else{
                                app->next=users;
                            }
                            users=app;
                            printf("Prima di Challenge\n");
                            char msg[]="REGOK\0";
                            sendMsg(msg,i,strlen(msg));
                            
                            char path [US_LENGTH+15];
                            sprintf(path,"CHALLENGE_%s.txt",username);
                            FILE * file=fopen(path,"w");
                            int challenge=rand();
                            fwrite(&challenge,1,sizeof(char *),file);
                           
                            printf("Dopo fclose\n");
                            char chall_recv[11];
                            int chall_resp;
                            recvMsg(chall_recv,i);
                            sscanf(chall_recv,"%d",&chall_resp);
                            if(challenge == chall_resp)
                                printf("YEEEEEEEE\n");
                            remove(path);
                            fclose(file);
                        }

                        //CHALLENGE FOR USERNAME
                       
                        strcpy(buffer,"");
                    }else{
                        // close(i);
                        // FD_CLR(i, &master);
                    }                
                }
            }
        }
    }
    return 0;
}