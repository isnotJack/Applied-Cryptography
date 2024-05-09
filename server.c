/*mettere tutto in inglese*/
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

int main(int argc, char** argv){    
    int listener, new_sd,len;
    int srv_port;
    int ret;
    int addrlen; 
    char buffer[1024];
    int fdmax; 
    int i;
    uint16_t lmsg; 
    struct sockaddr_in my_addr,cl_addr;
    fd_set master;
    fd_set read_fds;

    if (argc > 2){
        printf("Parametri non validi: chiusura programma\n");
        exit(1);
    }
    
    if (argc == 1)
        srv_port = 4242;            // server in ascolto sulla porta 4242
    else
        srv_port = atoi(argv[1]);   // server in ascolto sulla porta passata come parametro al comando
        
    
    listener = socket(AF_INET, SOCK_STREAM, 0); // creazione socket di ascolto 
    if (listener == -1){
        perror("Errore nella creazione del socket di ascolto ");
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
        perror("Errore nella bind ");
        exit(1);
    }
    ret = listen(listener, 10); //server in ascolto su socket listener con coda di max 10 client
    if (ret == -1){
        perror("Errore nella listen ");
        exit(1);
    }

    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(0, &master);             // aggiungo il descrittore 0 (stdin) al set dei socket monitorati
    FD_SET(listener, &master);      // aggiungo il listener al set dei socket monitorati
    fdmax = listener;               // il maggiore dei descrittori ora è il listener
    addrlen = sizeof(cl_addr);

    while (1){
        read_fds = master;
        ret = select(fdmax+1, &read_fds, NULL, NULL, NULL);
        if (ret == -1){
            perror("Errore nella select()");
            exit(1);
        }
        
        for (i = 0; i <= fdmax; i++){
            if (FD_ISSET(i, &read_fds)){
                if(i == listener){
                    new_sd = accept(listener, (struct sockaddr *) &cl_addr, &addrlen);
                    if (new_sd == -1){
                        printf("Errore nella creazione della connessione con il device");
                    }
                    FD_SET(new_sd, &master);
                    if(new_sd > fdmax){ fdmax = new_sd; } 
                }else{
                    ret = recv(i, (void*)&lmsg, sizeof(uint16_t), 0);
                    len = ntohs(lmsg); 
                    printf("sono len: %d\n", len);
                    ret = recv(i, (void*)buffer, len, 0);
                    printf("questo è il messaggio ricevuto %s",buffer);
                    //close(i);
                    FD_CLR(i, &master); 
                }
            }
        }
    }

    return 0;
}