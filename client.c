/*gestire la connessione come una funzione, date le richiesti di login e logout*/
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>        
#include "utility.h"

int MAX_LENGTH = 1024;
/*void wait_command(){
    printf("> ");
    fflush(stdout);
}*/

int start(){
    int choice;
    
    printf("Choose:\n");
    printf("[1] Registration\n");
    printf("[2] Login\n");

    
    while(1){
        printf("> ");
        scanf("%d", &choice);
        while(getchar() !='\n');
        if(choice != 1 && choice != 2){
            printf("Scelta non valida\n");
        }else{
            return choice;
        }
    }

}

void registration(char email[],char username[],char password[]){
    //inserire credenziali
    printf("Inserisci le tue credenziali\n");
    printf("email: ");
    fgets(email, MAX_LENGTH, stdin); // Leggo una riga da tastiera
    printf("username: ");  
    fgets(username, MAX_LENGTH, stdin); // Leggo una riga da tastiera
    printf("password: ");  
    fgets(password, MAX_LENGTH, stdin); // Leggo una riga da tastiera
   
    //generazione chiave pub associata legata allo username


    // mandare handshake
    //handshake();
    // mandare msg server
    // generare credenziali
    // mandare credenziali cifrate e con firma
    // numero causuale
}

void handshake(){

}

void help(){
    printf("[1] List(int n): lists the latest n available messages in the BBS");
    printf("\n[2] Get(int msg_id): downloads from the BBS the message specified by msg_id");
    printf("\n[3] Add(String title,String author,String body): adds a message to the BBS\n");
}

void menu_operation(){
    printf("Welcome, to interact insert the name of the function and after the parameter");
    printf("[1] List");
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
    char msg[MAX_LENGTH];
    int var=0;
    char email[MAX_LENGTH];
    char username[MAX_LENGTH];
    char password[MAX_LENGTH];


    if (argc != 2){
        printf("Parametri non validi, usa: ./dev <porta>\n");
        fflush(stdout);
        exit(1);
    }
    
    clt_port = atoi(argv[1]);

    // generazione chiave pubblica
    
    var = start();
    sd = socket(AF_INET,SOCK_STREAM,0);

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(clt_port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

    
    ret = connect(sd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret < 0){
        perror("Errore in fase di connessione: \n");
        exit(1);
    }

    if(var == 1){
        registration(email, username, password);
    }else{
        //login();
    }
    
    printf("Inserisci un messaggio: ");
    fgets(msg, sizeof(msg), stdin); 

    ret=sendLength(msg,sd);
    close(sd);

    return 0;
}