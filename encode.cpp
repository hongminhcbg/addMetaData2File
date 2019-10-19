#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "encode.h"
using namespace std;

#define NUM_ALPHA 60 //max = 180 (180/ 3 * 4 = 240)
#define MAX_LEN_B64 (256)
#define PRINTLOG 1
unsigned char buffer[NUM_ALPHA + 5];
unsigned char *encoded_data = (unsigned char*) malloc(256);
/**********************************/
// RSA config
 char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGeMDtmIvE98NuXVp2zlabOTtZrG\n"\
"e0CAG5LDQwW6d401OobeEGfJoSXvNpbtq4JmgvxH/lGGfUipQvyRG3bAzQ69Wqa/\n"\
"indhXLBK65vC7izjdcgzB6IVeBmyz/zy3cgKNT9r2bqhE5QWYB2W/Uv3PTtY0AWc\n"\
"2lfNTAX+LR0E41MxAgMBAAE=\n"\
"-----END PUBLIC KEY-----\n";
int padding = RSA_PKCS1_PADDING;
unsigned char  encrypted[512]={};

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};
//static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
int ReadfileBytes[12] = {120, 99, 72, 180, 60, 45, 90, 75, 150, 144, 0, 0};
/************************/
// public encrypt RSA
RSA * createRSA(unsigned char * key, int publicc)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(publicc)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

/****************************/
// encode base 64 function
unsigned char *base64_encode(const unsigned char *data, int input_length, int *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);
    memset(encoded_data, 0, MAX_LEN_B64);
    //unsigned char *encoded_data = (unsigned char*) malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}
/********************************************************************/

string getFileOutNameLHM(string fileIn){
    unsigned int index = 1000000;
    for(unsigned int i = 0; i < fileIn.length(); i++){
        if(fileIn[i] == '.'){
            index = i;
        }
    }
    if(index == 1000000){
        return fileIn;
    }
    string pos = fileIn.substr(0, index);
    string fileType = fileIn.substr(index, fileIn.length() - index);
    return pos + "_encode" + fileType;
}
/***************************************/
// exec command
std::string exec(const char* cmd) {
    char buffer[256];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

/********************************************************/

// convert char* to string
string getTitle(unsigned char *str, int length){
    string result = "";
    for(int i = 0; i < length; i++){
        result.push_back(str[i]);
    }
    #if PRINTLOG
        cout << "get title = " << result <<'\n'<< "title length = " << result.length() << endl;
    #endif
    return result;
}
/******************************************************/

int encodeMetaData(string fileIn){
    string fileOut = getFileOutNameLHM(fileIn);
    FILE * f1 = fopen(fileIn.c_str(), "rb");
    #if PRINTLOG
        printf("file in = %s\nfileout = %s\n", fileIn.c_str(), fileOut.c_str());
    #endif
    if(f1 == NULL){
        #if PRINTLOG
            printf(" flase open file\n");
        #endif
        return 0;
    }
//    int sumReadByte = 0;     
    int num = 0;
    unsigned char *enB64Poi = (unsigned char*) malloc(MAX_LEN_B64 + 5);
    int b64OutLen = 0; // output leng encode base 64
    int encrypted_length = 0;

    printf("\n\n\n----------------Begin Encript---------\n");


    memset(buffer, 0, NUM_ALPHA);
    num = fread(buffer, sizeof(char), NUM_ALPHA, f1);
    if ( num == NUM_ALPHA ) {  /* fread success */
        #if PRINTLOG
            printf("step1: Read first %d bytes success \n", NUM_ALPHA);
            cout << "data read first in file" << endl;
            for(int i = 1; i <= 60; i++){
                printf("%02X%c", buffer[i-1], (i%20==0) ? '\n' : '\t');
            }
        #endif

        buffer[NUM_ALPHA + 1] = '\0';
        memset(enB64Poi, 0, 256);
        enB64Poi = base64_encode(buffer, num, &b64OutLen); 
        if(enB64Poi != NULL){
            #if PRINTLOG
                printf("step2: encode base 64 first time success b64OutLen = %d\n", b64OutLen);
                for(int i = 1; i <= b64OutLen; i++){
                    printf("%02X%c", buffer[i-1], (i%20==0) ? '\n' : '\t');
                }
            #endif
        } else {
            #if PRINTLOG
                printf("step2: encode base 64 success false");
            #endif
            return 0;
        }

        memset(encrypted, 0, 256);
        encrypted_length = public_encrypt(enB64Poi, b64OutLen, (unsigned char*) publicKey, encrypted);
        if(encrypted_length == -1)
        {
            #if PRINTLOG
                printf("step3: encrypt data false" );                
            #endif
            return 0;
        } else {
            #if PRINTLOG
                printf("step3: encrypt data success, encrypted_length = %d\n", encrypted_length);                
            #endif
        }

        memset(enB64Poi, 0, 256);
        enB64Poi = base64_encode(encrypted, encrypted_length, &b64OutLen); 
        if(enB64Poi != NULL){
            #if PRINTLOG
                printf("step4: encode base 64 second time success b64OutLen = %d\n", b64OutLen);
            #endif
        } else {
            #if PRINTLOG
                printf("step4: encode base 64 second time false");
            #endif
            return 0;
        }

        // step 4 encode meta data by ffmpeg
        string title = getTitle(enB64Poi, b64OutLen);
        if(title.length() <= 0){
            #if PRINTLOG
                printf("step 4: get title flase\n");                
            #endif
            return 0;
        }
//        string cmd = "ffmpeg -i " + fileIn +  " -codec copy -strict -2 -metadata title=\"" + title + "\" " + fileOut + " -y";
        string cmd = "exiftool -overwrite_original -title=\"" + title + "\" \"" + fileIn + "\"";
        string resultCmd = exec(cmd.c_str());
        #if PRINTLOG            
            cout << "cmd = " << cmd << endl;               
            cout << "result cmd = " << resultCmd << endl;               
        #endif

        // cmd = "mv " + fileOut + " " + fileIn;
        // resultCmd = exec(cmd.c_str());
        return 1;

    } else {  /* fread failed */
        #if PRINTLOG
            printf("step1: Read first %d bytes false \n", NUM_ALPHA);
        #endif
        fclose(f1);
        return 0;
    }
}