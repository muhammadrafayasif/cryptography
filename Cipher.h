#include <iostream>
using std::string;

#ifndef CipherClass
#define CipherClass

class CipherInterface {
    protected:
        virtual string encrypt(string plaintext, string key) = 0;
        virtual string decrypt(string text, string key) = 0;
        virtual void preprocess(string& text, string& key) = 0;
        virtual void postprocess(string& text) = 0;
        virtual ~CipherInterface() = default;
        friend class Cipher;
};

class Cipher {
    private:
        CipherInterface* strategy;
    public:
        Cipher(CipherInterface* s) : strategy(s) {}
        void setMode(CipherInterface* s){
            if (strategy != s){
                delete strategy;
                strategy = s;
            }
        }
        string encrypt(string plaintext, string key){
            strategy->preprocess(plaintext, key);
            string result = strategy->encrypt(plaintext, key);
            strategy->postprocess(result);
            return result;
        }
        string decrypt(string text, string key){
            strategy->preprocess(text, key);
            string result = strategy->decrypt(text, key);
            strategy->postprocess(result);
            return result;
        }
        ~Cipher(){
            delete strategy;
        }
};

#endif
