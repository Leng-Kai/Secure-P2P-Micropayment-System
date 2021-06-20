#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <signal.h>

#define CRLF    "\r\n"
#define BLEN    1200

using namespace std;

extern unordered_map<string, User*> users;
extern char*    bptr;

void xor_with_bitmask(char* str)
{
    const int KEY = 127;
    int strLen = 256;
    for (int i = 0; i < strLen; ++i) {
        *(str + i) = (*(str + i) ^ KEY);
    }
}

void inform(string username, string inf) {
    
    int mysd;
    if ((mysd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\nSocket creation error.\n";
        return;
    }
    
    SSL_CTX*    myctx;
    SSL*        myssl;
    string key_path = "server_CA/server.key";
    string crt_path = "server_CA/server.crt";
    myctx = SSL_CTX_new(SSLv23_method());
    /* Load the client certificate into the SSL_CTX structure */
    SSL_CTX_use_certificate_file(myctx, crt_path.c_str(), SSL_FILETYPE_PEM);
    /* Load the private-key corresponding to the client certificate */
    SSL_CTX_use_PrivateKey_file(myctx, key_path.c_str(), SSL_FILETYPE_PEM);
    /* Check if the client certificate and private-key matches */
    if (!SSL_CTX_check_private_key(myctx)) {
        cout << "Private key does not match the certificate public key\n";
        exit(1);
    }
    /* Load the RSA CA certificate into the SSL_CTX structure */
    SSL_CTX_load_verify_locations(myctx, "CA.crt", NULL);
    SSL_CTX_set_verify(myctx, SSL_VERIFY_PEER, NULL);
    
    struct sockaddr_in newaddr;
    bzero(&newaddr, sizeof(newaddr));
    newaddr.sin_family = PF_INET;
    newaddr.sin_addr.s_addr = inet_addr(users[username]->_IP.c_str());
    newaddr.sin_port = htons(users[username]->_port);
    
    int myretcode;
    if ((myretcode = connect(mysd, (struct sockaddr *)&newaddr, sizeof(newaddr))) < 0) {
        cerr << "\nConnection error.\n";
        return;
    }
    
    myssl = SSL_new(myctx);
    SSL_set_fd(myssl, mysd);
    SSL_connect(myssl);
    
//    const char* req = inf.c_str();
    unsigned char* plaintext = (unsigned char*)inf.c_str();
    cout << "inform plaintext: " << plaintext << endl;
    
    FILE* fp = fopen("server_CA/server.key", "r");
    RSA* p_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    int len = RSA_size(p_key);
    char* ciphertext = new char[len + 1];
    memset(ciphertext, 0, len + 1);
    int r = RSA_private_encrypt(inf.length(), (const unsigned char*)inf.c_str(), (unsigned char*)ciphertext, p_key, RSA_PKCS1_PADDING);
    SSL_write(myssl, ciphertext, RSA_size(p_key));
    
    
//    send(mysd, req, strlen(req), 0);
    
    SSL_shutdown(myssl);
    close(mysd);
    SSL_free(myssl);
}

bool verify(string payername, string payeename, string amount, char* bptr) {
    RSA* key1 = users[payername]->getKey();
    RSA* key2 = users[payeename]->getKey();
    
    int len = RSA_size(key1);
    int len1 = 256;
    int len2 = 256;
    
    const char* c2text = bptr + 15 + payername.size() + payeename.size() + amount.size();
    
    char* c2_1text = new char[len + 1];
    char* c2_2text = new char[len + 1];
    memset(c2_1text, 0, len + 1);
    memset(c2_2text, 0, len + 1);
    memcpy(c2_1text, c2text, 256);
    memcpy(c2_2text, c2text + 256, 256);
    
    char* c1_1text = new char[len + 1];
    char* c1_2text = new char[len + 1];
    memset(c1_1text, 0, len + 1);
    memset(c1_2text, 0, len + 1);
    
    RSA_public_decrypt(len1, (unsigned char*)c2_1text, (unsigned char*)c1_1text, key2, RSA_PKCS1_PADDING);
    RSA_public_decrypt(len2, (unsigned char*)c2_2text, (unsigned char*)c1_2text, key2, RSA_PKCS1_PADDING);
    
    char* c1text = new char[len + 1];
    memset(c1text, 0, len + 1);
    memcpy(c1text, c1_1text, 200);
    memcpy(c1text + 200, c1_2text, 56);
    
    char* plaintext = new char[len + 1];
    memset(plaintext, 0, len + 1);
    
    RSA_public_decrypt(len, (unsigned char*)c1text, (unsigned char*)plaintext, key1, RSA_PKCS1_PADDING);
    
    string rmsg = string(plaintext);
    
    string rpayer, rpayee, ramount;
    size_t pos;
    pos = rmsg.find_first_of("#");
    rpayer = rmsg.substr(0, pos);
    rmsg = rmsg.substr(pos + 1);
    pos = rmsg.find_first_of("#");
    ramount = rmsg.substr(0, pos);
    rmsg = rmsg.substr(pos + 1);
    pos = rmsg.find_first_of(CRLF);
    rpayee = rmsg.substr(0, pos);
    rmsg = rmsg.substr(pos + 1);
    
    if ((rpayer  != payername) ||
        (rpayee  != payeename) ||
        (ramount != amount)) return false;

    return true;
}

#endif // UTIL_H
