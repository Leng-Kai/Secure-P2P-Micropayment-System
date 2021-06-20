#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <string.h>
#include <string>
#include <vector>
#include <deque>
#include <unistd.h>
#include "cmdParser.h"
#include "handleClient.h"
#include "../threadpool/threadpool.c"
#include "../threadpool/threadpool.h"
//#include "../ssl/ssl.h"

#define BLEN    1200
#define CRLF    "\r\n"
//#define THREAD  10
//#define QUEUE   256
#define NO_RESPONSE     "no response"
#define MAX_CONNECTION  2

using namespace std;

struct sockaddr_in servaddr;
int connection;

string      uid;
SSL_CTX*    ctx;
//SSL*        ssl;

int main(int argc, char* argv[]) {
//    system("rm *.key *.crt *.conf");
    int THREAD = 10;
    int QUEUE  = 256;
    
    if (argc > 1) {
        if (argc > 3) {
            cerr << "Too many arguments!\n";
            cerr << "usage: ./server [THREAD number] [QUEUE number]\n";
            return -1;
        }
        if (argc == 2 || argc == 3) {
            int t = atoi(argv[1]);
            if (t == 0) {
                cerr << "Invalid THREAD number.\n";
                cerr << "usage: ./server [THREAD number] [QUEUE number]\n";
                return -1;
            }
            THREAD = t;
        }
        if (argc == 3) {
            int q = atoi(argv[2]);
            if (q == 0) {
                cerr << "Invalid QUEUE number.\n";
                cerr << "usage: ./server [THREAD number] [QUEUE number]\n";
                return -1;
            }
            QUEUE = q;
        }
    }
    
    cout << "Max THREAD: " << THREAD << endl;
    cout << "Max QUEUE : " << QUEUE  << endl;
    
    int     PORT;
    cout << "\nport: ";           cin >> PORT;
    cout << endl;
    
    threadpool_t *pool;
    assert((pool = threadpool_create(THREAD, QUEUE, 0)) != NULL);
    
    if (PORT < 1025 | PORT > 65535) {
        cout << "socket: invalid port number.\n";
        cout << "(valid port numbers: " << 1025 << " to " << 65535 << ")\n";
        return -1;
    }
    
//    if ((uid = create_key_and_certificate("server")).size() == 0) {
//        cout << "failed to create private key and certificate.\n";
//        return -1;
//    }
    string key_path = "server_CA/server.key";
    string crt_path = "server_CA/server.crt";

    ctx = SSL_CTX_new(SSLv23_method());

    /* Load the client certificate into the SSL_CTX structure */
    if (SSL_CTX_use_certificate_file(ctx, crt_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cout << "failed to load certificate.\n";
        return -1;
    }
    /* Load the private-key corresponding to the client certificate */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cout << "failed to load private key.\n";
        return -1;
    }
    /* Check if the client certificate and private-key matches */
    if (!SSL_CTX_check_private_key(ctx)) {
        cout << "Private key does not match the certificate public key\n";
        return -1;
    }
    /* Load the RSA CA certificate into the SSL_CTX structure */
    if (!SSL_CTX_load_verify_locations(ctx, "server_CA/server_CA.crt", NULL)) {
        cout << "failed to load client certificate.\n";
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    int listenfd, connfd;
    
    if((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\nSocket creation error.\n";
        return -1;
    }
    
    int addrlen = sizeof(servaddr);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = PF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
    
    if (::bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        cerr << "\nbind socket error.\n";
//        system("rm *.key *.crt *.conf");
        return -1;
    }
    if (listen(listenfd, 10) < 0) {
        cerr << "\nlisten socket error.\n";
        return -1;
    }
    
    connection = 0;
    cout << "ready for connection\n";
    
    while (true) {
        if ((connfd = accept(listenfd, (struct sockaddr*)&servaddr, (socklen_t*) &addrlen)) < 0) {
            cerr << "\naccept socket error.\n";
            return -1;
        }
        
//        ssl = SSL_new(ctx);
//        SSL_set_fd(ssl, connfd);
        
//        threadpool_add(pool, &handleClient, (void*)ssl, 0);
        threadpool_add(pool, &handleClient, (void*)&connfd, 0);
//        close(connfd);
    }
    close(listenfd);
    SSL_CTX_free(ctx);
    
    return 0;
}
