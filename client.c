/*gestire la connessione come una funzione, date le richiesti di login e logout*/
#include "utility.h"

//GLOBAL FOR SCOPE
EVP_PKEY * pubkey;         // per contenere la chiave pubblica da inviare al server
EVP_PKEY * serverKey;      // per la chiave pubblica del server (utile per verificare la sua firma)
// Variabili per Diffie-Hellman
EVP_PKEY * dh_params;



int start(){
    int choice;
    
    printf("Select one of the following options:\n");
    printf("[1] Registration\n");
    printf("[2] Login\n");
    
    while(1){
        printf("> ");
        scanf("%d", &choice);
        while(getchar() !='\n');
        if(choice != 1 && choice != 2){
            printf("Invalid choice, try again.\n");
        }else{
            return choice;
        }
    }
}

void handshake(char * username,int sd){
    EVP_PKEY_CTX * DH_ctx;
    EVP_PKEY* DH_keys;
    EVP_PKEY * priv_key;        // per la chiave privata usata per firmare
    pubkey = retrieve_pubkey(username,0);
    sendMsg("HANDSHAKE",sd);
    send_public_key(sd, pubkey);    // invio al server della chiave pubblica RSA
    printf("Dopo send public key\n");

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
    int signature_lenght=Digital_Signature(priv_key,DH_keys,signature);

        printf("signature len %d\n",signature_lenght);

    send_public_key(sd,DH_keys);
    sendMsg(signature,sd);

}

void registration(char email[],char username[],char password[],int sd){
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

    // generazione coppia di chiavi associata all'username
    // questo trucco permette di simulare "offline" il meccanismo dei certificati
    // è come se si creasse la coppia di chiavi e la chiave pubblica fosse contenuta all'interno di un certificato
    keys_generation(username);
    
    handshake(username, sd);     // esecuzione protocollo di handshake

    // mandare credenziali cifrate e con firma

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

    if(var == 1){
        registration(email, username, password,sd);
    }else{
        //login();
    }
    
    close(sd);

    return 0;
}