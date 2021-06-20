#ifndef CMDPARSER_H
#define CMDPARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unistd.h>
#include <signal.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "cmdExecStatus.h"
#include "typeID.h"
#include "util.h"
//#include "ssh.h"

#define BLEN    1200
#define CRLF    "\r\n"
#define FROM    5000
#define TO      7999

using namespace std;

extern int      sd;
extern char     buf[BLEN];
extern char*    bptr;
extern int      n;
extern int      buflen;
extern pid_t    pid;

extern vector<string>   res;

string  cmd, param1, param2, param3;
TypeID  type;
size_t  pos;
int     paramCnt;
int     statusCode;
string  user = "";
int     mysd = -1;
bool    getResponse;

unordered_map<string, string>   userIP;
unordered_map<string, int>      userPort;

string toLower(string str) {
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] <= 'Z' & str[i] >= 'A') {
            str[i] = str[i] - ('Z' - 'z');
        }
    }
    return str;
}

TypeID typeId(string type) {
    return toLower(type) == "help"          ? TYPE_HELP     :
           toLower(type) == "reg"           ? TYPE_REG      :
           toLower(type) == "register"      ? TYPE_REG      :
           toLower(type) == "login"         ? TYPE_LOGIN    :
           toLower(type) == "list"          ? TYPE_LIST     :
           toLower(type) == "trans"         ? TYPE_TRANS    :
           toLower(type) == "transaction"   ? TYPE_TRANS    :
           toLower(type) == "exit"          ? TYPE_EXIT     :
           TYPE_ERROR;
}

void getParam(string &param) {
    pos = cmd.find_first_not_of(" ");
    if (pos == string::npos) {
        return;
    }
    cmd = cmd.substr(pos);
    pos = cmd.find_first_of(" ");
    param = (cmd.substr(0, pos));
    cmd = cmd.substr(pos == string::npos ? cmd.size() : pos);
}

void parseParam() {
    paramCnt = 0;
    pos = cmd.find_first_not_of(" ");
    if (pos == string::npos) {
        type = TYPE_ERROR;
        return;
    }
    
    cmd = cmd.substr(pos);
    pos = cmd.find_first_of(" ");
    type = typeId(cmd.substr(0, pos));
    cmd = cmd.substr(pos == string::npos ? cmd.size() : pos);
    
    getParam(param1);
    getParam(param2);
    getParam(param3);
    
    paramCnt = param3 != "" ? 3:
               param2 != "" ? 2:
               param1 != "" ? 1:
               0;
//    cout << type << endl << param1 << endl << param2 << endl << param3 << endl;
}

void updateUserList(string data) {
    string user, userip;
    int userport;

    pos = data.find_first_of("#");
    user = data.substr(0, pos);
    data = data.substr(pos + 1);

    pos = data.find_first_of("#");
    userip = data.substr(0, pos);
    data = data.substr(pos + 1);

    pos = data.find_first_of(CRLF);
    userport = stoi(data.substr(0, pos));

    userIP[user] = userip;
    userPort[user] = userport;
}

CmdExecStatus handle_HELP() {
    cout << endl;
    cout << "commands:\n";
    cout << "    reg   : create a new account\n";
    cout << "    login : log in to your account\n";
    cout << "    list  : list the user(s) online\n";
    cout << "    trans : make transaction with another user\n";
    cout << "    exit  : quit the system\n";
    return CMD_EXEC_DONE;
}

CmdExecStatus handle_REG() {
    if (paramCnt < 2) {
        cout << "usage: reg <user account name> <deposit amount>\n";
        return CMD_EXEC_ERROR;
    }
    if (paramCnt > 2) {
        cout << "reg: too many arguments\n";
        return CMD_EXEC_ERROR;
    }
    if (!isValidString(param1)) {
        cout << "reg: invalid user name \"" + param1 << "\"\n";
        return CMD_EXEC_ERROR;
    }
    if (param1.size() > 30) {
        cout << "reg: length of user name should not be greater than 30\n";
        return CMD_EXEC_ERROR;
    }
    if (!isNonNegInt(param2)) {
        cout << "reg: deposit amount should be a non-negative integer\n";
        return CMD_EXEC_ERROR;
    }
    
    sendRequest("REGISTER#" + param1 + "#" + param2 + CRLF);
//    for (int i = 0; i < res.size(); ++i) {
//        cout << res[i] << endl;
//    }
    statusCode = stoi(res[0].substr(0, res[0].find_first_of(" ")));
    
    switch (statusCode) {
        case 100:
            cout << "account successfully created.\n";
            break;
            
        case 210:
        default:
            cout << "failed to create account.\n";
            break;
    }
    
    return CMD_EXEC_DONE;
}

CmdExecStatus handle_LOGIN() {
    if (paramCnt < 2) {
        cout << "usage: login <user account name> <port number>\n";
        return CMD_EXEC_ERROR;
    }
    if (paramCnt > 2) {
        cout << "login: too many arguments\n";
        return CMD_EXEC_ERROR;
    }
    if (!isValidPort(param2, FROM, TO)) {
        cout << "login: invalid port number.\n";
        cout << "(valid port numbers: " << FROM << " to " << TO << ")\n";
        return CMD_EXEC_ERROR;
    }
    if (user != "") {
        cout << "You had already logged in an account!\n";
        return CMD_EXEC_ERROR;
    }
    
    sendRequest(param1 + "#" + param2 + CRLF);
//    for (int i = 0; i < res.size(); ++i) {
//        cout << res[i] << endl;
//    }
    if (res[0].substr(0, 13) == "220 AUTH_FAIL") {
        cout << "failed to log in.\n";
        return CMD_EXEC_ERROR;
    }
    if (res[0].substr(0, 5) == "This ") {
        cout << res[0] << endl;
        return CMD_EXEC_ERROR;
    }
    
    user = param1;
    
//    if (!create_key_and_certificate(user)) {
//        cout << "failed to create private key and certificate.\n";
//        return CMD_EXEC_ERROR;
//    }
    
    listenToPort(stoi(param2));
    unsigned int microsecond = 1000000;
    usleep(0.1 * microsecond); // sleeps for 0.1 second
    
    cout << "\nwelcome, " << user << "!\n";
    cout << "account balance: " << res[0] << "\n\n";
    cout << res[1] << " user(s) are currently online:\n\n";
    for (size_t i = 2; i < res.size(); i += 2) {
        cout << res[i] << endl;
//        updateUserList(res[i]);
        cout << "deposit amount: " << res[i + 1] << "\n\n";
    }
    
    return CMD_EXEC_DONE;
}

CmdExecStatus handle_LIST() {
    if (!user.size()) {
        cout << "Please log in first!\n";
        return CMD_EXEC_ERROR;
    }
    if (paramCnt > 0) {
        cout << "list: too many arguments\n";
        return CMD_EXEC_ERROR;
    }
    
    sendRequest("List\r\n");
    
    if (res[0].substr(0, 7) == "Please ") {
        cout << res[0] << endl;
        return CMD_EXEC_ERROR;
    }
    
    cout << "\nuser name: " << user << "\n";
    cout << "account balance: " << res[0] << "\n\n";
    cout << res[1] << " user(s) are currently online:\n\n";
    for (size_t i = 2; i < res.size(); i += 2) {
        cout << res[i] << endl;
//        updateUserList(res[i]);
        cout << "deposit amount: " << res[i + 1] << "\n\n";
    }
    
    return CMD_EXEC_DONE;
}

CmdExecStatus handle_TRANS() {
    if (!user.size()) {
        cout << "Please log in first!\n";
        return CMD_EXEC_ERROR;
    }
    if (paramCnt < 2) {
        cout << "usage: trans <pay amount> <payee user name>\n";
        return CMD_EXEC_ERROR;
    }
    if (paramCnt > 2) {
        cout << "trans: too many arguments\n";
        return CMD_EXEC_ERROR;
    }
    if (!isPosInt(param1)) {
        cout << "trans: pay amount should be a positive integer\n";
        return CMD_EXEC_ERROR;
    }
    if (!isValidString(param2)) {
        cout << "trans: invalid user name \"" + param2 << "\"\n";
        return CMD_EXEC_ERROR;
    }
    
    sendRequest("List");
    for (size_t i = 2; i < res.size(); i += 2) {
        updateUserList(res[i]);
    }
    
    if (res[0].substr(0, 7) == "Please ") {
        cout << res[0] << endl;
        return CMD_EXEC_ERROR;
    }
    if (userIP.find(param2) == userIP.end()) {
        cout << "user does not exist!\n";
        return CMD_EXEC_ERROR;
    }
    
    int mysd;
    if ((mysd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\nSocket creation error.\n";
        return CMD_EXEC_ERROR;
    }
    
//    cout << "userIP: " << userIP[param2] << endl;
//    cout << "userPort: " << userPort[param2] << endl;
    
    SSL_CTX*    myctx;
    SSL*        myssl;
    string key_path = "client_CA/client.key";
    string crt_path = "client_CA/client.crt";
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
    newaddr.sin_addr.s_addr = inet_addr(userIP[param2].c_str());
    newaddr.sin_port = htons(userPort[param2]);
    
    int myretcode;
    if ((myretcode = connect(mysd, (struct sockaddr *)&newaddr, sizeof(newaddr))) < 0) {
        cerr << "\nUser " + param2 + " is not online.\n";
        close(mysd);
        return CMD_EXEC_ERROR;
    }
    
    myssl = SSL_new(myctx);
    SSL_set_fd(myssl, mysd);
    SSL_connect(myssl);
    
    string mycmd = user + "#" + param1 + "#" + param2 + CRLF;
    unsigned char* plaintext = (unsigned char*)mycmd.c_str();
    
    FILE* fp = fopen("client_CA/client.key", "r");
    RSA* p_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    int len = RSA_size(p_key);
    char* ciphertext = new char[len + 1];
    memset(ciphertext, 0, len + 1);
    RSA_private_encrypt(mycmd.length(), (const unsigned char*)mycmd.c_str(), (unsigned char*)ciphertext, p_key, RSA_PKCS1_PADDING);
    
    getResponse = false;
    bool received = false;                // wait until receive response
//    send(mysd, req, strlen(req), 0);    // work after implementing
    SSL_write(myssl, ciphertext, RSA_size(p_key));
    while (!received) {                   // with thread
        received = getResponse;
    }
    
    SSL_shutdown(myssl);
    close(mysd);
    SSL_free(myssl);
    
//    cout << "transaction with " << param2 << " is done.\n";

    return CMD_EXEC_DONE;
}

CmdExecStatus handle_EXIT() {
    if (paramCnt > 0) {
        cout << "exit: too many arguments\n";
        return CMD_EXEC_ERROR;
    }
    
    string sure;
    cout << "Are you sure you want to exit? [y/n]: ";
    getline(cin, sure);
    
    if (sure == "Y" | sure == "y") {
        if (pid) kill(pid, SIGKILL);
        sendRequest("Exit\r\n");
        cout << "Bye!\n";
        
        return CMD_EXEC_QUIT;
    }
    
    return CMD_EXEC_DONE;
}


CmdExecStatus cmdParser(string prompt) {
    cout << prompt;
    getline(cin, cmd);
    
    param1 = param2 = param3 = "";
    parseParam();
    
    if (type == TYPE_ERROR) {
        cout << "Invalid command.\n"
             << "Try 'help' for help.\n";
        return CMD_EXEC_ERROR;
    }
    
    CmdExecStatus status = CMD_EXEC_DONE;
    
    switch (type) {
        case TYPE_HELP:
            status = handle_HELP();
            break;
            
        case TYPE_REG:
            status = handle_REG();
            break;
            
        case TYPE_LOGIN:
            status = handle_LOGIN();
            break;
            
        case TYPE_LIST:
            status = handle_LIST();
            break;
            
        case TYPE_TRANS:
            status = handle_TRANS();
            break;
            
        case TYPE_EXIT:
            status = handle_EXIT();
            break;
            
        default:
            status = CMD_EXEC_ERROR;
            break;
    }
    
    return status;
}

#endif // CMDPARSER_H
