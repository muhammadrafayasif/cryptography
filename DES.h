#include <sstream>
#include <bitset>
#include <vector>
#include <cmath>
#include <iomanip>
#include "Cipher.h"
using 
std::vector, std::stringstream, std::stoi, std::hex,
std::bitset, std::uppercase, std::setw, std::setfill, std::invalid_argument;

#ifndef DEStandard
#define DEStandard

class DES : public CipherInterface {
    private:
        bool is_encrypting = false;
        vector<string> keys;
        vector<int> round_shifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

        // Helper methods

        string to_bin(char _hex){
            stringstream ss;
            ss << hex << _hex;
            int dec;
            ss >> dec;
            return bitset<4>(dec).to_string();
        }
        string dec_to_bin(int _dec, int bits){
            if (bits==4) return bitset<4>(_dec).to_string();
            else if (bits==28) return bitset<28>(_dec).to_string();
            else if (bits==48) return bitset<48>(_dec).to_string();
            else if (bits==32) return bitset<32>(_dec).to_string();
            else return bitset<4>(_dec).to_string();
        }
        string bin_to_hex(string _bin){
            stringstream ss;
            ss << hex << uppercase << bin_to_dec(_bin);
            return ss.str();
        }
        unsigned long long bin_to_dec(string _bin){
            return stoull(_bin, 0, 2);
        }
        string bin_to_string(string _bin){
            string result;
            for (int i = 0; i < _bin.length(); i += 8) {
                bitset<8> bits(_bin.substr(i, 8));
                result += static_cast<char>(bits.to_ulong());
            }
            return result;
        }
        string shift(string& bin, int times){
            times=times%(bin.length());
            bin = bin.substr(times) + bin.substr(0, times);
            return bin;
        }
        void preprocess(string& pt, string& ky){
            string plaintext;
            if (pt.length()==16) {
                for (int i=0; i<16; i++) plaintext+=to_bin(pt[i]);
            }
            else if (pt.length()<16){
                stringstream ss;
                for (int i=0; i<pt.length(); i++){
                    ss << hex << setw(2) << setfill('0') << uppercase << (int)pt[i];
                }
                pt = ss.str();
                for (int i=0; i<16; i++) plaintext+= (pt.length()>i) ? to_bin(pt[i]) : to_bin('0');
            } else throw invalid_argument("Plaintext size is invalid (must be less than 8 for string and 16 characters for HEX)");
            pt = plaintext;
        }
        void postprocess(string& text){
            text = apply_final_permutation(text, is_encrypting);
            if (is_encrypting && text.length()==16) return;
            else if (is_encrypting && text.length()<16)
                text = string(16 - text.length(), '0') + text;
        }

        // Encryption methods

        string apply_initial_permutation(string pt){
            string res;
            for (int i=0; i<64; i++) res += pt[IP[i]-1];
            return res;
        }
        void apply_permutation_1(string& ky){
            string res;
            for (int i=0; i<56; i++) res += ky[PC1[i]-1];
            ky = res;
        }
        void apply_permutation_2(string& ky){
            string res;
            for (int i=0; i<48; i++) res += ky[PC2[i]-1];
            ky = res;
        }
        void key_generation(string ky){
            keys.clear();
            string key;
            for (int i=0; i<16; i++) 
                key+=(i>ky.length()) ? to_bin(ky[i]) : to_bin('0');
            apply_permutation_1(key);
            string LK = key.substr(0, 28), RK = key.substr(28, 28);
            for (auto round : round_shifts){
                string round_key = shift(LK, round) + shift(RK, round);
                apply_permutation_2(round_key);
                keys.push_back(round_key);
            }
        }
        string expansion_permutation(string RPT){
            string res;
            for (int i=0; i<48; i++) res += RPT[EP[i]-1];
            return res;
        }
        void key_mixing(string& RPT, int round){
            string res;
            for (int i=0; i<RPT.length(); i++){
                if (RPT[i]=='0' && keys[round-1][i]=='0') res += '0';
                else if (RPT[i]=='1' && keys[round-1][i]=='1') res += '0';
                else res += '1';
            }
            RPT = res;
        }
        void apply_s_boxes(string& RPT){
            vector<string> groups; string buffer, res;
            for (int i=1; i<=RPT.length(); i++){
                buffer+=RPT[i-1];
                if (i%6==0){
                    groups.push_back(buffer);
                    buffer.clear();
                }
            }
            for (int i=0; i<8; i++){
                int row = bin_to_dec(string(1, groups[i][0]) + string(1, groups[i][5]));
                int col = bin_to_dec(string(1, groups[i][1]) + string(1, groups[i][2]) + string(1, groups[i][3]) + string(1, groups[i][4]));
                buffer += dec_to_bin(SBOX[i][row][col], 4);
            }
            RPT = buffer;
        }
        void apply_permutation_table(string& RPT){
            string res;
            for (int i=0; i<32; i++) res += RPT[P[i]-1];
            RPT = res;
        }
        string xor_with_left_half(string LPT, string RPT){
            string res;
            for (int i=0; i<RPT.length(); i++){
                if (RPT[i]=='0' && LPT[i]=='0') res += '0';
                else if (RPT[i]=='1' && LPT[i]=='1') res += '0';
                else res += '1';
            }
            return res;
        }
        void swap(string& LPT, string& RPT){
            string temp = LPT;
            LPT = RPT;
            RPT = temp;
        }
        string apply_final_permutation(string plaintext, bool is_encrypting=false){
            string res;
            for (int i=0; i<64; i++) res += plaintext[FP[i]-1];
            return (is_encrypting) ? bin_to_hex(res) : bin_to_string(res);
        }

        // Encryption / Decryption

        string crypt(string pt, string ky){
            string plaintext = apply_initial_permutation(pt);
            string LPT = plaintext.substr(0,32), RPT = plaintext.substr(32,32);
            key_generation(ky);
            for (
                    int round=((is_encrypting) ? 1 : 16);
                    (is_encrypting) ? round<=16 : round>=1;
                    (is_encrypting) ? round++ : round--
                ){
                string R = expansion_permutation(RPT);
                key_mixing(R, round);
                apply_s_boxes(R);
                apply_permutation_table(R);
                string LPT_prev = LPT;
                LPT = RPT;
                RPT = xor_with_left_half(LPT_prev, R);
            }

            return RPT + LPT;
        }

        string encrypt(string pt, string ky){
            is_encrypting = true;
            return crypt(pt, ky);
        }
        string decrypt(string pt, string ky){
            is_encrypting = false;
            return crypt(pt, ky);
        }

    public:
        const static int IP[64], PC1[56], PC2[48], EP[48], P[32], SBOX[8][4][16], FP[64];
};

const int DES::IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

const int DES::PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

const int DES::PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

const int DES::EP[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

const int DES::P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

const int DES::SBOX[8][4][16] = {
    {
        { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6,  12,  5,  9, 0,  7 },
        {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
        {  4,  1, 14,  8, 13, 11,  2, 12,  9,  7,  3, 15, 10,  6,  5,  0 },
        { 15, 12,  8,  2,  4,  9,  1, 14,  7,  5, 11,  3, 10,  0,  6, 13 }
    },
    {
        { 15,  1,  8, 14,  6, 11,  3,  4, 13,  7,  10,  9,  5,  0, 12,  2 },
        {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
        {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
        {  2, 12,  4,  1, 14,  7,  10, 11, 15,  9,  8,  0,  3,  5, 13,  6 }
    },
    {
        { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
        { 13, 15,  0,  3, 10,  1,  7,  4,  9,  8, 14,  5,  2, 11, 12,  6 },
        {  1, 15, 13,  8, 10,  3, 12,  7, 11,  4, 14,  9,  5,  0,  2,  6 },
        {  7,  4, 13,  1, 10, 14,  0,  9,  3, 12, 15,  6,  5, 11,  8,  2 }
    },
    {
        {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8, 15,  5, 11, 12,  4 },
        {  9,  7,  3, 15, 13,  8, 14, 12,  4,  2,  1, 10, 11,  6,  0,  5 },
        { 15,  1,  8, 14,  6, 11,  3,  4, 13,  7, 10,  9,  2, 12,  5,  0 },
        {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  2, 11,  7, 14,  5, 12 }
    },
    {
        {  2, 12,  4,  1,  7, 10, 11,  6,  8, 15,  9, 14,  3,  5,  0, 13 },
        { 14, 11,  2, 12,  4,  7, 13,  1, 10, 15,  9,  5,  0,  6,  3,  8 },
        {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5, 14,  0,  3,  6 },
        { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15, 10,  9,  0,  5,  3,  4 }
    },
    {
        { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
        { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0,  3, 11,  8 },
        {  9, 14, 15,  5,  1,  3,  8,  12,  7, 11,  4,  2, 13,  0,  6, 10 },
        {  3,  9,  6,  15, 10,  1, 13,  8, 14,  4,  7,  5, 11, 12,  0,  2 }
    },
    {
        {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
        { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12, 15,  8,  2,  6 },
        {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  9,  5,  0,  6,  8,  2 },
        {  6, 11,  8,  9,  1, 10, 12,  3, 15,  5, 14,  7,  4, 13,  0,  2 }
    },
    {
        { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
        {  1, 15, 13,  8, 10,  3,  7,  4,  12,  5,  6, 11, 14,  9,  0,  2 },
        {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
        {  2, 12,  4,  1, 14,  7, 10, 11,  6,  0,  9,  5,  3,  8, 13, 15 }
    }
};

const int DES::FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

#endif