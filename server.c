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
    
    DH_retrival(dh_params);         // Recover p and g

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
                        DH_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
                       
                        my_prvkey = NULL;
                        EVP_PKEY_keygen_init(DH_ctx);
                        EVP_PKEY_keygen(DH_ctx, &my_prvkey);
                        printf("Private/public pair for DH generated\n");

                        priv_key = retrieve_privkey("server");
                        printf("Prima della firma\n");
                        Digital_Signature(priv_key, my_prvkey);

                    }
                    
                    //close(i);
                    FD_CLR(i, &master); 
                }
            }
        }
    }
    return 0;
}