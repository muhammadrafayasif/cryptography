#include <iostream>
using std::string;

#ifndef CipherClass
#define CipherClass

class CipherInterface {
    public:
        virtual string encrypt(string plaintext, string key) = 0;
        virtual string decrypt(string text, string key) = 0;
        virtual ~CipherInterface() = default;
};

class Cipher {
    private:
        CipherInterface* strategy;
    public:
        Cipher(CipherInterface* s) : strategy(s) {}
        void setMode(CipherInterface* s){
            strategy = s;
        }
        string encrypt(string plaintext, string key){
            return strategy->encrypt(plaintext, key);
        }
        string decrypt(string text, string key){
            return strategy->decrypt(text, key);
        }
};

#endif