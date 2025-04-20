#include <sstream>
#include <vector>
#include <random>
#include <ctime>
#include "Cipher.h"
using std::hex, std::uppercase, std::string, std::stringstream;
int d;

#ifndef RSAEnc
#define RSAEnc

class RSA : public CipherInterface {
    private:
        int p, q, n, phi;

        // Helper methods

        string to_hex(int _n){
            stringstream ss;
            ss << hex << uppercase << _n;
            string res = ss.str();
            return res;
        }

        int hex_to_int(string _hex){
            stringstream ss;
            int _n;
            ss << hex << _hex;
            ss >> _n;
            return _n;
        }

        int gcd(int a, int b) {
            while (b != 0) {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        int mod_inv(int e, int phi) {
            int t1 = 0, t2 = 1;
            int r1 = phi, r2 = e;

            while (r2 > 0) {
                int quotient = r1 / r2;
                int temp = t1;
                t1 = t2;
                t2 = temp - quotient * t2;

                temp = r1;
                r1 = r2;
                r2 = temp % r2;
            }

            if (r1 > 1) {
                return -1;
            }
            if (t1 < 0) {
                t1 = t1 + phi;
            }
            return t1;
        }

        long long pow(long long c, long long d, long long n) {
            long long result = 1;
            c = c % n;
            while (d > 0) {
                if (d % 2 == 1) {
                    result = (result * c) % n;
                }
                d = d >> 1;
                c = (c * c) % n;
            }
            return result;
        }

        void initialize(int key){
            srand(time(NULL));
            do {
                int _p = rand() % 123, _q = rand() % 123;
                p = prime[_p]; q = prime[_q];
                n = p*q;
                phi = (p-1)*(q-1);
            } while (gcd(key, phi)!=1);
        }

        // Encryption method

        string _encrypt(string plaintext, int key){
            string res;
            for (int i=0; i<plaintext.length(); i++)
                res += (to_hex( pow((int)plaintext[i], key, n) )) + " ";
            res+="\nmod=";
            res+=std::to_string(n);
            res+="\nprivate key=";
            res+=std::to_string(mod_inv(key, phi));
            return res;
        }

        // Decryption method

        string _decrypt(string text, int key, int mod){
            string res, buffer;
            for (int i=0; i<text.length(); i++){
                buffer+=text[i];
                if (text[i]==' ' || i==text.length()-1){
                    res += pow(hex_to_int(buffer), key, mod);
                    buffer.clear();
                }
            }
                
            return res;
        }

    public:
        const static int prime[123];
        string encrypt(string plaintext, string key){
            initialize(stoi(key));
            return _encrypt(plaintext, stoi(key));
        }
        string decrypt(string text, string key){
            int mod;
            std::cout << "Enter mod: ";
            std::cin >> mod;
            initialize(stoi(key));
            return _decrypt(text, stoi(key), mod);
        }
};

const int RSA::prime[123] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 
    167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 
    367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 
    463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 
    587, 593, 599, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683
};

#endif