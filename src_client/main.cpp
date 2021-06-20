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
#include <vector>
#include "cmdExecStatus.h"
#include "cmdParser.h"
#include "util.h"
//#include "../ssl/ssl.h"

#define BLEN    1200
//#define IP      "127.0.0.1"
//#define PORT    8080
#define S       string("")
#define CRLF    "\r\n"

using namespace std;

string prompt = "cmd> ";

char    buf[BLEN];
char*   bptr = buf;
int     n = 0;
int     buflen = BLEN;
int     sd;

string      uid;
SSL_CTX*    ctx;
SSL*        ssl;

int main(int argc, char* argv[]) {
    
    string  IP;
    int     PORT;
    cout << "ip address: ";     cin >> IP;
    cout << "port: ";           cin >> PORT;    cout << endl;
    
    if (!isValidIP(IP)) {
        cout << "socket: invalid IP address\n";
        return -1;
    }
    if (PORT < 1025 | PORT > 65535) {
        cout << "socket: invalid port number.\n";
        cout << "(valid port numbers: " << 1025 << " to " << 65535 << ")\n";
        return -1;
    }
    
//    if ((uid = create_key_and_certificate("client")).size() == 0) {
//        cout << "failed to create private key and certificate.\n";
//        return -1;
//    }
    string key_path = "client_CA/client.key";
    string crt_path = "client_CA/client.crt";
    
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
    if (!SSL_CTX_load_verify_locations(ctx, "CA.crt", NULL)) {
        cout << "failed to load server certificate.\n";
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\nSocket creation error.\n";
        return -1;
    }
    
    struct sockaddr_in remaddr;
    bzero(&remaddr, sizeof(remaddr));
    remaddr.sin_family = PF_INET;
    remaddr.sin_addr.s_addr = inet_addr(IP.c_str());
    remaddr.sin_port = htons(PORT);
    
    int retcode;
    if ((retcode = connect(sd, (struct sockaddr *)&remaddr, sizeof(remaddr))) < 0) {
        cerr << "\nConnection error.\n";
//        system("rm *.key *.crt *.conf");
        return -1;
    }
    
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sd);
    SSL_connect(ssl);

//    n = recv(sd, bptr, buflen, 0);
    memset(buf, 0, sizeof(buf));
    SSL_read(ssl, bptr, buflen);
    
    cout << buf << endl;
//    if (string(buf) == "FULL\r\n") {
//        cout << "The server can not handle the connection now.\n";
//        cout << "Pleasr try again later.\n\n";
//        return -1;
//    }
    if (string(buf) == "CONNECTED\r\n") {
        cout << "Successfully connected.\n\n";
    }
    
    
    memset(buf, 0, sizeof(buf));
    cin.ignore();
    
    CmdExecStatus status = CMD_EXEC_DONE;
    while (status != CMD_EXEC_QUIT) {
        status = cmdParser(prompt);
        cout << endl;
    }
    
//    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    system((S + "rm " + key_path + " " + crt_path + " " + uid + "_client_ssl.conf").c_str());
    
    return 0;
}
