#ifndef CMDPARSER_H
#define CMDPARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unistd.h>
#include <signal.h>
#include "typeID.h"
#include "user.h"
#include "util.h"

#define BLEN    1200
#define CRLF    "\r\n"
#define NO_RESPONSE "no response"
#define NO_OUTPUT   "NOOUTPUT\r\n"

using namespace std;

unordered_map<string, User*> users;
unordered_map<string, User*> IP_user;

TypeID typeId(string type) {
    return type == "REGISTER"      ? TYPE_REG      :
           type == "List"          ? TYPE_LIST     :
           type == "Exit"          ? TYPE_EXIT     :
           type == "TRANSACTION"   ? TYPE_TRANS    :
           TYPE_LOGIN;
}

string getParam(string &cmd) {
    string param;
    size_t pos;
    if (cmd == CRLF)
        return "";
    if ((pos = cmd.find_first_of("#")) == string::npos)
        pos = cmd.find_first_of(CRLF);
    param = cmd.substr(0, pos);
    cmd = cmd.substr(pos + 1);
    return param;
}

bool isLoginRequest(string cmd) {
    int cnt = 0;
    for (char c: cmd)
        if (c == '#')
            cnt++;
    return cnt == 1;
}

string handle_REG(string username, string deposit_amount) {
    if (users[username]) return "210 FAIL\r\n";
    
    User* newUser = new User(username, deposit_amount);
    users[username] = newUser;
    return "100 OK\r\n";
}

string handle_LIST(string username);

string handle_LOGIN(string clientIP, string username, string port, RSA* rsa_key) {
    if (!users[username]) return "220 AUTH_FAIL\r\n";
    
    if (!users[username]->login(clientIP, port, rsa_key)) return "This user has already login.\r\n";
    cout << "login status: " << users[username]->online() << endl;
    return handle_LIST(username);
}

string handle_LIST(string username) {
    if (username == "") return "Please login first!\r\n";
    string response = "";
    string list = "";
    
    response += (users[username]->getDamount() + CRLF);
    
    int onlineUserCnt = 0;
    
    // iterate the map to find online users
    // and append their details to the list
    
    for (auto i: users) {
        if (i.second->online()) {
            onlineUserCnt++;
            list += i.second->detail() + CRLF;
            list += i.second->getDamount() + CRLF;
        }
    }
    
    return response + to_string(onlineUserCnt) + CRLF + list;
}

string handle_TRANS(string payername, string payeename, string amount, char* bptr) {
    if (payername == payeename) {
        return string("Can not make transaction with yourself!") + CRLF;
    }
    if (!users[payeename]->online()) {
        return string("User ") + payeename + " is not online." + CRLF;
    }
    // verify
    if (!verify(payername, payeename, amount, bptr)) {
        inform(payername, string("Illegal transaction.") + CRLF);
        return NO_OUTPUT;
    }
    // verify
    if (!users[payername]->transaction(stoi(amount) * -1)) {
        
        // send a message to the payer to inform him that
        // his deposit amount is not enough.
        
        inform(payername, string("Deposit amount not enough.") + CRLF);
        
        return NO_OUTPUT;
    }
    users[payeename]->transaction(stoi(amount));
    
    inform(payername, string("Transaction done with ") + payeename + "." + CRLF);
    return "\nReceived " + amount + " from " + payername + ".\n" + CRLF;
}

string handle_EXIT(string username) {
    if (username != "") {
        users[username]->logout();
    }
    return string("Bye") + CRLF;
}

string cmdParser(string username, string clientIP, string rec, RSA* rsa_key, char* bptr) {
    
    string cmd = rec;
//    cout << "cmd: " << cmd << endl;
    if (cmd == "") return NO_RESPONSE;
    
    string param1 = getParam(cmd);
    string param2 = getParam(cmd);
    string param3 = getParam(cmd);
    string param4 = getParam(cmd);
    TypeID type = typeId(param1);
    
//    cout << "p1: " << param1 << endl;
//    cout << "p2: " << param2 << endl;
//    cout << "p3: " << param3 << endl;
//    cout << "p4: " << param4 << endl;
    
//    if (type == TYPE_ERROR) {
//        cout << "Invalid command.\n";
//        return "error";
//    }
    
    if (param2 != "" && param3 == "") {
        type = TYPE_LOGIN;
    }
    
    string response = "no response";
    
    switch (type) {
        case TYPE_REG:
            response = handle_REG(param2, param3);
            break;
            
        case TYPE_LOGIN:
            response = handle_LOGIN(clientIP, param1, param2, rsa_key);
            break;
            
        case TYPE_LIST:
            response = handle_LIST(username);
            break;
            
        case TYPE_TRANS:    // TRANSACTION#<PayerName>#<Amount>#<PayeeName><CRLF>
            response = handle_TRANS(param2, param4, param3, bptr);
            break;
            
        case TYPE_EXIT:
            response = handle_EXIT(username);
            break;
            
        default:
            response = "error";
            break;
    }
    
    return response;
}

#endif // CMDPARSER_H
