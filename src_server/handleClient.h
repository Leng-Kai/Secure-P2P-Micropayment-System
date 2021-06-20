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
#include <queue>
#include <unistd.h>
#include "cmdParser.h"

#define BLEN        1200
#define CRLF        "\r\n"
#define NO_RESPONSE "no response"
#define NO_OUTPUT   "NOOUTPUT\r\n"

using namespace std;

extern struct sockaddr_in servaddr;
extern unordered_map<string, User*> users;
extern int connection;

extern SSL_CTX* ctx;

void handleClient(/*void* ssl_ptr*/ void* connfd_ptr) {
    
    int     connfd = *(int*)connfd_ptr;
//    SSL* ssl = (SSL*)ssl_ptr;
    char    buf[BLEN];
    char*   bptr = buf;
    int     n = 0;
    int     buflen = BLEN;
    string  clientIP;
    string  username = "";
    string  response;
    
    SSL*    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connfd);
    SSL_accept(ssl);
    
    X509* crt = SSL_get_peer_certificate(ssl);
    EVP_PKEY* p_key = X509_get_pubkey(crt);
    RSA* rsa_key = EVP_PKEY_get1_RSA(p_key);
    
    const char* res = "CONNECTED\r\n";
//    send(connfd, res, strlen(res), 0);
    SSL_write(ssl, res, strlen(res));
    
    struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&servaddr;
    struct in_addr ipAddr = pV4Addr->sin_addr;
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipAddr, cip, INET_ADDRSTRLEN);
    clientIP = string(cip);
    cout << "client IP: " << clientIP << "\n\n";
    
    while (response != "Bye\r\n") {
//        SSL_accept(ssl);
//        cout << "ready for request\n";
        memset(buf, 0, sizeof(buf));
        n = SSL_read(ssl, bptr, buflen);
        if (n == -1) continue;
        if (!(n/* = recv(connfd, bptr, buflen, 0)SSL_read(ssl, bptr, buflen)*/)) {
            cerr << ((username == "") ? ("A user") : (string("User ") + username));
            cerr << " (" << clientIP << ") disconnected.\n\n";
            
            // logout the user.
            
            if (username != "") {
                users[username]->logout();
            }
            
            break;
        }
        string rec = string(buf);
//        memset(buf, 0, sizeof(buf));
        
        cout << rec << endl;
        
        response = cmdParser(username, clientIP, rec, rsa_key, bptr);
        cerr << "response: " << response << endl;
        
        if (isLoginRequest(rec) &&
            response != "220 AUTH_FAIL\r\n" &&
            response != "this user has already login\r\n") {
            username = rec.substr(0, rec.find_first_of("#"));
        }
        
        if (response == NO_RESPONSE) {
            continue;
        }
        
        const char* res = response.c_str();
//        send(connfd, res, strlen(res), 0);
        SSL_write(ssl, res, strlen(res));
    }
    SSL_shutdown(ssl);
//    close(connfd);
    SSL_free(ssl);
}
