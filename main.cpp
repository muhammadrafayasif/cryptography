#include "AES.h"
#include "DES.h"
#include "RSA.h"
#include <iostream>
using namespace std;

int main(){
    // Initializing all cryptography algorithms
    AES AESEncryption; 
    DES DESEncryption;
    RSA RSAEncryption;
    string input, type, text, key;
    cout << "Enter cryptography type (AES, DES, RSA): ";
    getline(cin, input);
    transform(input.begin(), input.end(), input.begin(), ::tolower);
    Cipher app(&AESEncryption);
    if (input=="des") app.setMode(&DESEncryption);
    else if (input=="rsa") app.setMode(&RSAEncryption);
    cout << "Encryption (e) or Decryption (d): ";
    getline(cin, type);
    transform(type.begin(), type.end(), type.begin(), ::tolower);
    cout << "Enter text: "; getline(cin, text);
    cout << "Enter key: "; getline(cin, key);
    if (type=="d") cout << app.decrypt(text, key);
    else cout << app.encrypt(text, key);

}