#include <vector>
#include <algorithm>
#include <map>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include "Cipher.h"
using std::vector, std::stringstream, std::hex, std::setw, std::uppercase, std::setfill;

#ifndef AdavancedES
#define AdvancedES

class AES : public CipherInterface {
    private:
        bool is_encrypting = false;
        vector<vector<uint8_t>> state{4, vector<uint8_t>(4, 0)};
        vector<vector<vector<uint8_t>>> keys{11, vector<vector<uint8_t>>{4, vector<uint8_t>(4,0)}};
        
        // Helper methods

        string to_hex(uint8_t ui){
            stringstream ss;
            ss << hex << setw(0) << setfill('0') << uppercase << (int)ui;
            string res = ss.str();
            if (res.length()==1) res.insert(0, 1 , '0');
            return res;
        }
        uint8_t gfmul(uint8_t a, uint8_t b) {
            uint8_t result = 0;
            while (b > 0) {
                if (b & 1) result ^= a;
                bool msb_set = (a & 0x80); 
                a <<= 1;  
                if (msb_set) a ^= 0x1B;
                b >>= 1; 
            }
            return result;
        }
        void preprocess(string& text, string& key){
            if (text.length()==32){
                int k=0;
                for (int i=0; i<32; i+=2, k++){
                    string bit; bit+=text[i]; bit+=text[i+1];
                    try {
                        text[k] = stoi(bit, 0, 16);
                    } catch(...){
                        throw std::invalid_argument("Text is in invalid hex format.");
                    }
                }
                text.resize(32, 0);
            }

            if (key.length()==32){
                int k=0;
                for (int i=0; i<32; i+=2, k++){
                    string bit; bit+=key[i]; bit+=key[i+1];
                    try {
                        text[k] = stoi(bit, 0, 16);
                    } catch(...){
                        throw std::invalid_argument("Text is in invalid hex format.");
                    }
                }
                text.resize(32, 0);
            }

            int k=0;
            for (int i=0; i<4; i++){
                for (int j=0; j<4; j++){
                    state[j][i] = (text.length()>k) ? (uint8_t)text[k] : 0;
                    keys[0][j][i] = (key.length()>k) ? (uint8_t)key[k] : 0;
                    k++;
                }
            }
        }

        void postprocess(string& text){
            // No post processing is needed.
        }
        string process(){
            string cipher;
            for (int i=0; i<4; i++){
                for (int j=0; j<4; j++){
                    if (is_encrypting) cipher += to_hex(state[j][i]);
                    else cipher += state[j][i];
                }
            }
            return cipher;
        }

        // Encryption/Decryption methods

        void key_expansion(){
            for (int r=1; r<=10; r++){
                vector<uint8_t> word = {keys[r-1][0][3], keys[r-1][1][3], keys[r-1][2][3], keys[r-1][3][3]};
                uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
                // Word n (4) = Rcon + 0
                rotate(word.begin(), word.begin()+1, word.end());
                word[0] = sbox[word[0]]; word[1] = sbox[word[1]]; word[2] = sbox[word[2]]; word[3] = sbox[word[3]];
                word[0] ^= rcon[r-1];
                word[0] ^= keys[r-1][0][0]; 
                word[1] ^= keys[r-1][1][0]; 
                word[2] ^= keys[r-1][2][0]; 
                word[3] ^= keys[r-1][3][0];
                keys[r][0][0] = word[0]; 
                keys[r][1][0] = word[1];
                keys[r][2][0] = word[2];
                keys[r][3][0] = word[3];
                // Word n+1 (5) = 4 + 1
                keys[r][0][1] = keys[r][0][0]^keys[r-1][0][1];
                keys[r][1][1] = keys[r][1][0]^keys[r-1][1][1];
                keys[r][2][1] = keys[r][2][0]^keys[r-1][2][1];
                keys[r][3][1] = keys[r][3][0]^keys[r-1][3][1];
                // Word n+2 (6) = 5 + 2
                keys[r][0][2] = keys[r][0][1]^keys[r-1][0][2];
                keys[r][1][2] = keys[r][1][1]^keys[r-1][1][2];
                keys[r][2][2] = keys[r][2][1]^keys[r-1][2][2];
                keys[r][3][2] = keys[r][3][1]^keys[r-1][3][2];
                // Word n+3 (7) = 6 + 3
                keys[r][0][3] = keys[r][0][2]^keys[r-1][0][3];
                keys[r][1][3] = keys[r][1][2]^keys[r-1][1][3];
                keys[r][2][3] = keys[r][2][2]^keys[r-1][2][3];
                keys[r][3][3] = keys[r][3][2]^keys[r-1][3][3];
            }
        }
        void add_round_key(int rnd){
            for(int i=0; i<4; i++)
                for (int j=0; j<4; j++)
                    state[i][j] ^= keys[rnd][i][j];
        }

        // Encryption methods
        
        void sub_bytes(){
            for(int i=0; i<4; i++)
                for (int j=0; j<4; j++)
                    state[i][j] = sbox[state[i][j]];
        }
        void shift_rows(){
            rotate(state[1].begin(), state[1].begin()+1, state[1].end());
            rotate(state[2].begin(), state[2].begin()+2, state[2].end());
            rotate(state[3].begin(), state[3].begin()+3, state[3].end());
        }
        void mix_columns(){
            for (int col=0; col<4; col++){
                uint8_t a = state[0][col], b = state[1][col], c = state[2][col], d = state[3][col];
                state[0][col] = gfmul(2, a) ^ gfmul(3, b) ^ c ^ d;
                state[1][col] = a ^ gfmul(2, b) ^ gfmul(3, c) ^ d;
                state[2][col] = a ^ b ^ gfmul(2, c) ^ gfmul(3, d);
                state[3][col] = gfmul(3, a) ^ b ^ c ^ gfmul(2, d);
            }
        }
        void _encrypt(string plaintext, string key){
            key_expansion();
            add_round_key(0);
            for (int rnd=1; rnd<=9; rnd++){
                sub_bytes();
                shift_rows();
                mix_columns();
                add_round_key(rnd);
            }
            sub_bytes();
            shift_rows();
            add_round_key(10);
        }

        // Decryption methods

        void inv_sub_bytes(){
            for(int i=0; i<4; i++)
                for (int j=0; j<4; j++)
                    state[i][j] = inv_sbox[state[i][j]];
        }
        void inv_shift_rows(){
            rotate(state[1].rbegin(), state[1].rbegin()+1, state[1].rend());
            rotate(state[2].rbegin(), state[2].rbegin()+2, state[2].rend());
            rotate(state[3].rbegin(), state[3].rbegin()+3, state[3].rend());
        }
        void inv_mix_columns(){
            for (int col=0; col<4; col++){
                uint8_t a = state[0][col], b = state[1][col], c = state[2][col], d = state[3][col];
                state[0][col] = gfmul(0x0e, a) ^ gfmul(0x0b, b) ^ gfmul(0x0d, c) ^ gfmul(0x09, d);
                state[1][col] = gfmul(0x09, a) ^ gfmul(0x0e, b) ^ gfmul(0x0b, c) ^ gfmul(0x0d, d);
                state[2][col] = gfmul(0x0d, a) ^ gfmul(0x09, b) ^ gfmul(0x0e, c) ^ gfmul(0x0b, d);
                state[3][col] = gfmul(0x0b, a) ^ gfmul(0x0d, b) ^ gfmul(0x09, c) ^ gfmul(0x0e, d);
            }
        }
        void _decrypt(string text, string key){
            key_expansion();
            add_round_key(10);
            for (int rnd=9; rnd>=1; rnd--){
                inv_shift_rows();
                inv_sub_bytes();
                add_round_key(rnd);
                inv_mix_columns();
            }
            inv_shift_rows();
            inv_sub_bytes();
            add_round_key(0);
        }

        // Encryption / Decryption
        string encrypt(string plaintext, string key){
            _encrypt(plaintext, key);
            is_encrypting = true;
            return process();
        }
        string decrypt(string text, string key){
            _decrypt(text, key);
            is_encrypting = false;
            return process();
        }

    public:
        static const uint8_t sbox[256];
        static const uint8_t inv_sbox[256];
        
};

#endif

const uint8_t AES::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

const uint8_t AES::inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};