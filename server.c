/*mettere tutto in inglese*/
#include "utility.h"
EVP_PKEY * priv_key;
// definizione variabili per Diffie-Hellman
EVP_PKEY * dh_params;
EVP_PKEY_CTX * DH_ctx;      
EVP_PKEY* my_prvkey;

int main(int argc, char** argv){    
    int listener, new_sd,len;
    int srv_port;
    int ret;
    int addrlen; 
    char buffer[KEY_LENGTH];
    int fdmax; 
    int i;
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
    
    //DH_retrival(dh_params);         // Recover p and g

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
                        // ricezione chiave pubblica del client (certificato)
                        int size = recvMsg(buffer,i);
                        insertFile(buffer, size, i);
                        printf("Client certificate received \n");

                        // Invio chiave pubblica server

                        // DH_ctx = DH_PubPriv(dh_params, DH_pubkey);   // generazione parametro privato b e pubblic g^b
                         
                        // Genearation of public/private pair
                        dh_params = EVP_PKEY_new();
                        EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
                        DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
                       
                        my_prvkey = NULL;
                        my_prvkey = EVP_PKEY_new();
                        EVP_PKEY_keygen_init(DH_ctx);
                        EVP_PKEY_keygen(DH_ctx, &my_prvkey);

                        FILE* file2 = fopen("prova.pem", "w");
                        if(!file2) { 
                            printf("Error opening the file4\n");
                            exit(1);
                        }
                        if (PEM_write_PUBKEY(file2, my_prvkey) == 0) {
                            perror("Error writing public key to file.\n");
                            fclose(file2);
                            exit(1);
                        }else{
                            printf("Successaa\n");
                        }
                        EVP_PKEY* my_pubkey = PEM_read_PUBKEY(file2,NULL, NULL, NULL);
                        fclose(file2);
                        printf("Private/public pair for DH generated\n");
                        priv_key = retrieve_privkey("server");
                        printf("Prima della firma\n");
                        //Digital_Signature(priv_key, my_pubkey);
                        unsigned char* signature;
                        int signature_len;
                        signature = malloc(EVP_PKEY_size(priv_key));
                        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                        EVP_SignInit(ctx, EVP_sha256());
                        //da mettere in una funzione
                        BIO *bio = BIO_new(BIO_s_mem()); // Creazione di un BIO in memoria
                        if (!bio) {
                            return 1 ; // Errore nella creazione del BIO
                        }
                        
                            printf("almeno qui ci arrivo\n");

                        // Scrittura della chiave pubblica nel BIO
                        if (!PEM_write_bio_PUBKEY(bio, my_pubkey)) {
                            BIO_free(bio); // Liberare la memoria del BIO
                            return 1; // Errore nella scrittura della chiave pubblica nel BIO
                        }
                        // Ottieni il puntatore al buffer di dati BIO
                        char *buffer_data;
                        long buffer_length = BIO_get_mem_data(bio, &buffer_data);
                        
                        BIO_free(bio); // Liberare la memoria del BIO
                        printf("stampa di buffer_length %s: \n", buffer_length );
                        //fin qui


                        EVP_SignUpdate(ctx, (unsigned char*)buffer_data,buffer_length);
                        EVP_SignFinal(ctx, signature, &signature_len,priv_key);
                        printf("Firma eseguita %s: \n", signature);
                        EVP_MD_CTX_free(ctx);

                    }
                    
                    //close(i);
                    FD_CLR(i, &master); 
                }
            }
        }
    }
    return 0;
}