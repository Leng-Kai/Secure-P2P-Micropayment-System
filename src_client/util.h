#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include "../threadpool/threadpool.c"
#include "../threadpool/threadpool.h"

#define CRLF    "\r\n"
#define BLEN    1200
#define NO_OUTPUT   "NOOUTPUT"
#define THREAD  2
#define QUEUE   2

using namespace std;

extern int      sd;
extern char     buf[BLEN];
extern char*    bptr;
extern int      n;
extern int      buflen;
extern string   prompt;
extern string   user;
extern bool     getResponse;
extern SSL*     ssl;

vector<string>  res;
pid_t           pid;
int             listen_port;

void xor_with_bitmask(char* str)
{
    const int KEY = 127;
    int strLen = 256;
    for (int i = 0; i < strLen; ++i) {
        *(str + i) = (*(str + i) ^ KEY);
    }
}

bool isValidString(string str) {
    string test1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    string test2 = test1 + "0123456789_";
    
    string s = str.substr(0, 1);
    if (test1.find_first_of(s) == string::npos) {
        return false;
    }
    
    for (size_t i = 1; i < str.size(); ++i) {
        s = str.substr(i, 1);
        if (test2.find_first_of(s) == string::npos) {
            return false;
        }
    }
    
    return true;
}

bool isNonNegInt(string str) {
    string test = "0123456789";
    string s;
    
    for (size_t i = 0; i < str.size(); ++i) {
        s = str.substr(i, 1);
        if (test.find_first_of(s) == string::npos) {
            return false;
        }
    }
    
    return true;
}

bool isPosInt(string str) {
    return isNonNegInt(str) ? (stoi(str) > 0) : false;
}

bool isValidPort(string str, int from = 5000, int to = 7999) {
    return (isNonNegInt(str) & (stoi(str) >= from) & (stoi(str) <= to));
}

bool isValidIP(string str) {
    size_t pos;
    
    for (int i = 0; i < 3; ++i) {
        pos = str.find_first_of(".");
        if ((pos == string::npos) | !isValidPort(str.substr(0, pos), 0, 255)) {
            cout << "invalid IP address.\n";
            return false;
        }
        str = str.substr(pos + 1);
    }
    if (!isValidPort(str, 0, 255)) {
        cout << "invalid IP address.\n";
        return false;
    }
    
    return true;
}

void parseRes(string ress) {
    size_t pos;
    while (ress.size() > 2) {
        pos = ress.find_first_not_of(CRLF);
        ress = ress.substr(pos);
        pos = ress.find_first_of(CRLF);
        res.push_back(ress.substr(0, pos));
        ress = ress.substr(pos + 1 > ress.size() ? pos : pos + 1);
    }
}

void sendRequest(string cmd, char* text = nullptr) {
//    cmd += CRLF;
//    send(sd, req, strlen(req), 0);
    if (!text) {
        const char* req = cmd.c_str();
        SSL_write(ssl, req, strlen(req));
    }
    else {
        char* req = new char[cmd.size() + 513];
        memcpy(req, cmd.c_str(), strlen(cmd.c_str()) + 1);
        memcpy(req + strlen(cmd.c_str()), text, 513);
        SSL_write(ssl, req, cmd.size() + 513);
    }
//    cerr << "send request: " << cmd << endl;
    
//    n = recv(sd, bptr, buflen, 0);
    memset(buf, 0, sizeof(buf));
    SSL_read(ssl, bptr, buflen);
//    cerr << (string(buf)) << endl;
    res.clear();
    parseRes(string(buf));
//    memset(buf, 0, sizeof(buf));
}

void* listen_on_port(void* port_ptr) {
//    int port = *(int*)port_ptr;
    int port = listen_port;
//    cout << "port: " << port << endl;
    int listenfd, connfd;
    
    if((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\nSocket creation error.\n";
        exit(1);
    }
    
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = PF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    
    if (::bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        cerr << "\nbind socket error.\n";
        exit(1);
    }
    if (listen(listenfd, 10) < 0) {
        cerr << "\nlisten socket error.\n";
        exit(1);
    }
    
    while (true) {
//        cout << "waiting for connection ...\n";
        if ((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) < 0) {
            cerr << "\naccept socket error.\n";
            continue;
        }
//        cout << "get transaction message!\n";
        getResponse = false;
        
        SSL_CTX*    myctx = SSL_CTX_new(SSLv23_method());
        SSL*        myssl;
        string key_path = "client_CA/client.key";
        string crt_path = "client_CA/client.crt";
        string CA_path  = "CA.crt";
        /* Load the client certificate into the SSL_CTX structure */
        SSL_CTX_use_certificate_file(myctx, crt_path.c_str(), SSL_FILETYPE_PEM);
        /* Load the private-key corresponding to the client certificate */
        SSL_CTX_use_PrivateKey_file(myctx, key_path.c_str(), SSL_FILETYPE_PEM);
        /* Check if the client certificate and private-key matches */
        SSL_CTX_check_private_key(myctx);
        if (!SSL_CTX_load_verify_locations(myctx, "CA.crt", NULL)) {
            cout << "failed to load client certificate.\n";
            exit(1);
        }
        SSL_CTX_set_verify(myctx, SSL_VERIFY_PEER, NULL);
        
        myssl = SSL_new(myctx);
        SSL_set_fd(myssl, connfd);
        SSL_accept(myssl);
        
        X509* crt = SSL_get_peer_certificate(myssl);
        EVP_PKEY* p_key = X509_get_pubkey(crt);
        RSA* rsa_key = EVP_PKEY_get1_RSA(p_key);
        int len = RSA_size(rsa_key);
        
        memset(buf, 0, sizeof(buf));
//        n = recv(connfd, bptr, buflen, 0);
        SSL_read(myssl, bptr, buflen);
        
        if (!string(buf).size()) {
            getResponse = true;
            continue;
        }
        
        char* plaintext = new char[len + 1];
        char* ciphertext = bptr;
        RSA_public_decrypt(RSA_size(rsa_key), (unsigned char*)ciphertext, (unsigned char*)plaintext, rsa_key, RSA_PKCS1_PADDING);
        
//        string rec = string(buf);
        string c1text = string(ciphertext);
        string rec = string(plaintext);
        if (!rec.size()) {
            getResponse = true;
            continue;
        }
        if (rec.find_first_of(" ") != string::npos) {
            getResponse = true;
            cerr << endl;
            
            size_t pos = rec.find_first_of(".");
            rec = rec.substr(0, pos + 1);
            cerr << rec;
//            cout.flush();
//            cerr << prompt;
            continue;
        }
        string usr, amount;
        size_t pos;
        pos = rec.find_first_of("#");
        usr = rec.substr(0, pos);
        rec = rec.substr(pos + 1);
        pos = rec.find_first_of("#");
        amount = rec.substr(0, pos);
        
        char* c1_1text = new char[len + 1];
        char* c1_2text = new char[len + 1];
        memset(c1_1text, 0, len + 1);
        memset(c1_2text, 0, len + 1);
        memcpy(c1_1text, ciphertext, 200);
        memcpy(c1_2text, ciphertext + 200, 56);
        
        FILE* fp = fopen("client_CA/client.key", "r");
        rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        len = RSA_size(rsa_key);
        unsigned char* c2_1text = new unsigned char[len + 1];
        unsigned char* c2_2text = new unsigned char[len + 1];
        memset(c2_1text, 0, len + 1);
        memset(c2_2text, 0, len + 1);
        RSA_private_encrypt(200, (const unsigned char*)c1_1text, (unsigned char*)c2_1text, rsa_key, RSA_PKCS1_PADDING);
        RSA_private_encrypt(56, (const unsigned char*)c1_2text, (unsigned char*)c2_2text, rsa_key, RSA_PKCS1_PADDING);
        
        char* c2text = new char[2 * len + 1];
        memset(c2text, 0, 2 * len + 1);
        memcpy(c2text, c2_1text, 256);
        memcpy(c2text + 256, c2_2text, 256);
        
        
        sendRequest("TRANSACTION#" + usr + "#" + amount + "#" + user + "#", c2text);
        
        if (res[0] != NO_OUTPUT) {
            cerr << endl << res[0] << endl << prompt;
        }
//            cout << "\nreceived " + amount + " from user " + usr << ".\n\n";
//            cerr << prompt;  // TOFIX
        
        // report to server
        
//        SSL_shutdown(myssl);
        close(connfd);
        SSL_free(myssl);
    }
    
    close(listenfd);
}

void listenToPort(int port) {
    int portref = port;
    listen_port = port;
    pthread_t       tid;
    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    pthread_create(&tid, &attr, listen_on_port, (void*)&portref);
}

#endif // UTIL_H
