#ifndef USER_H
#define USER_H

using namespace std;

class User {
    friend void inform(string username, string inf);
public:
    User(string username, string deposit_amount) {
        this->_username = username;
        this->_damount  = stoi(deposit_amount);
        this->_login    = false;
        this->_IP       = "";
        this->_port     = 0;
    }
    ~User() {}

    bool login(string IP, string port, RSA* rsa_key) {
        if (this->_login) return false;
        this->_login = true;
        this->_IP    = IP;
        this->_port  = stoi(port);
        this->_key   = rsa_key;
        return true;
    }
    
    bool logout() {
        this->_login = false;
        this->_IP    = "";
        this->_port  = 0;
        return true;
    }
    
    bool online() { return this->_login; }
    
    string getDamount() { return to_string(this->_damount); }
    
    RSA* getKey() { return this->_key; }
    
    string detail() {
        return this->_username + "#" + this->_IP + "#" + to_string(this->_port);
    }
    
    bool transaction(int amount) {
        if (this->_damount + amount < 0) return false;
        this->_damount += amount;
        return true;
    }
    
private:
    string  _username;
    int     _damount;
    bool    _login;
    string  _IP;
    int     _port;
    RSA*    _key;
};

#endif // USER_H
