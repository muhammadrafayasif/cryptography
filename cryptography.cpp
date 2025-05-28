#include "AES.h"
#include "DES.h"
#include "RSA.h"
#include <iostream>
#include <cstring>
#include <fstream>
using namespace std;

string removeZeroPadding(const string& decrypted) {
    int end = decrypted.find_last_not_of('\0');
    return (end == string::npos) ? "" : decrypted.substr(0, end + 1);
}

void lower(char* s){
    int len = strlen(s);
    for (int i=0; i<len; i++)
        s[i] = tolower(s[i]);
}

int main(int argc, char** argv){
    // Local based encryption/decryption
    if (argc==1) {

        cout << "cryptography [file1] [file2] ... [fileN] [encrypt|decrypt] [aes|des|rsa]" << endl << endl;
        cout << "No files given, entering local mode.." << endl;
        string input, type, text, key;
        while (1) {
            cout << "Enter cryptography type (AES : default, DES, RSA, q : quit): "; getline(cin, input);
            transform(input.begin(), input.end(), input.begin(), ::tolower);
            if (input=="q") return 0;
            Cipher app(new AES());
            if (input=="des") app.setMode(new DES());
            else if (input=="rsa") app.setMode(new RSA());
            cout << "Encryption (e : default) or Decryption (d): ";
            getline(cin, type);
            transform(type.begin(), type.end(), type.begin(), ::tolower);
            cout << "Enter text: "; getline(cin, text);
            cout << "Enter key: "; getline(cin, key);
            try {
                if (type=="d") cout << app.decrypt(text, key);
                else cout << app.encrypt(text, key);
            }
            catch(std::out_of_range){
                cout << "\nAn exception occurred!" << endl;
                cout << "Key size was out of int range." << endl;
            }
            catch(const exception& e){
                cout << "\nAn exception occurred!" << endl;
                cout << e.what() << endl;
            }
            cout << "\n\nRestarting program.. (Press q to quit)\n\n";
        }

    // File based encryption/decryption
    } else if (argc>=4){

        char type[4], method[8];
        strncpy(type, argv[argc-1], 4);
        strncpy(method, argv[argc-2], 8);
        type[sizeof(type)-1] = '\0';
        method[sizeof(method)-1] = '\0';
        lower(type); lower(method);
        if (
            strcmp(method, "encrypt") && strcmp(method, "decrypt")
        )
            throw invalid_argument("Expected [encrypt|decrypt]\n cryptography [file1] [file2] ... [fileN] [encrypt|decrypt] [aes|des|rsa]\n");
        else if (
            strcmp(type, "aes") && strcmp(type, "des") && strcmp(type, "rsa")
        )
            throw invalid_argument("Expected [aes|des|rsa]\n cryptography [file1] [file2] ... [fileN] [encrypt|decrypt] [aes|des|rsa]\n");

        string key;
        Cipher app(new AES());
        if (!strcmp(type, "des")) app.setMode(new DES());
        else if (!strcmp(type, "rsa")) app.setMode(new RSA());

        string buffer, text;
        int block_size;

        if (!strcmp(method, "encrypt")){
            if (!strcmp(type, "aes")) block_size = 16;
            else if (!strcmp(type, "des")) block_size = 8;
            else block_size = INT_MAX;
        } else {
            if (!strcmp(type, "aes")) block_size = 32;
            else if (!strcmp(type, "des")) block_size = 16;
            else block_size = INT_MAX;
        }

        for (int i=1; i<argc-2; i++){
            cout << "Enter key " << "(file " << i << "): "; getline(cin, key);
            ifstream fi(argv[i]);

            if (fi.is_open()){
                while (getline(fi, buffer))
                    text += buffer;
            }
            if (!strcmp(type, "rsa")) block_size = text.length();

            string result;
            for (int i=0; i<text.length(); i+=block_size){
                try {
                    if (!strcmp(method, "encrypt"))
                        result += app.encrypt(text.substr(i, block_size), key);
                    else
                        result += app.decrypt(text.substr(i, block_size), key);
                } catch(const exception& e){
                    cout << "\nAn exception occurred!" << endl;
                    cout << e.what() << endl;
                }
            }
            result = removeZeroPadding(result);

            ofstream fo(argv[i]);
            if (fo.is_open()) fo << result;
            
            fi.close();
            fo.close();
            text.clear();
        }

    } else throw invalid_argument("Invalid arguments.\ncryptography [file1] [file2] ... [fileN] [encrypt|decrypt] [aes|des|rsa]\n");

}