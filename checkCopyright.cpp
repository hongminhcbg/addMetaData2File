#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <string>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdexcept>
#include <fstream>

#include "checkCopyright.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <netpacket/packet.h>
#include "jsmn.h"
using namespace std;

#define uc unsigned char
#define ll long long int
#define PRINT_LOG 1
#define NUM_ALPHA (256)
#define FIRST_READ (60)
#define MAX_LEN_B64 (256)
#define MAX_FIRST_READ (10)
#define MAX_LEN_DECRYPT (256)

uc buffer[NUM_ALPHA + 1];
int ReadfileBytes[12] = {120, 99, 72, 180, 60, 45, 90, 75, 150, 144, 0, 0};
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};
static char *decoding_table = NULL;

/*****************RSA config*****************/
unsigned char decrypted[MAX_LEN_DECRYPT]={};
int padding = RSA_PKCS1_PADDING;

unsigned char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";

unsigned char privateKeyMeta[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIICWwIBAAKBgGeMDtmIvE98NuXVp2zlabOTtZrGe0CAG5LDQwW6d401OobeEGfJ\n"\
"oSXvNpbtq4JmgvxH/lGGfUipQvyRG3bAzQ69Wqa/indhXLBK65vC7izjdcgzB6IV\n"\
"eBmyz/zy3cgKNT9r2bqhE5QWYB2W/Uv3PTtY0AWc2lfNTAX+LR0E41MxAgMBAAEC\n"\
"gYAWSR2VEgm9bbV/B9nN5R43yQ2n7xntyuSkVKQjInvCh3c+OaL8Q3gMawyrtSFZ\n"\
"omiElZYVw8VJEyzYoP5xM5OuV1q3PmmBt3M+8NMcJwaDDWDC0CMLDFqzjGGwUtDC\n"\
"FW/ZWQd9EXktc79gTRkjW906DVnC17yAS0G0ql7EzvJu8QJBAKQ+OsTApywl4lF/\n"\
"hh5Vkx4BZ/9ql9ompGKNEUh0fOQ+aZfZgNLFk2Qbcu/inmuMPh3JaHHi/qtq19+i\n"\
"ysa0uDUCQQChZTDYkA8Y1CwwA+gDLgG3TSIF4QsKjgZ0TVyn57m2Sn2a7GLzokpw\n"\
"g+9ptt1xQUMF/wF4uyCVJc4f7hF0OiaNAkEAhD67EStSL8D9PsPgmNIsl+9n7ofE\n"\
"Z1nP6K5PaTiqSxlZ6nOuP4foiqVzYWXmSxBr/43pdDHi/uETmrU4ctCWtQJAfK1R\n"\
"/YnTz8df1zu9SG+K7dINHWOKhv3OKJv2ntKYmSSUQVCo5DKTtLWHBjA4gpv6rbAf\n"\
"r+dGtVD+GZZsL1AYpQJAeIFTI7ad3R120D/fZPXYW1+/k+i5qaSYHW0mN26NW9nS\n"\
"tZXmSuHn0Iirq4Z/oJnmt7Jpk4OLPZQuWQGXv5s5Ow==\n"\
"-----END RSA PRIVATE KEY-----\n";

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
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

/*********************************/
// decode base 64 funtion
void build_decoding_table() {
    decoding_table = (char*) malloc(256);

    for (int i = 0; i < 64; i++){
        decoding_table[(unsigned char) encoding_table[i]] = i;
    }    
}

unsigned char *base64_decode(unsigned char *data, int inputLength, int *output_length) {
    if (decoding_table == NULL) build_decoding_table();
    *output_length = inputLength / 4 * 3;
    if (data[inputLength - 1] == '=') (*output_length)--;
    if (data[inputLength - 2] == '=') (*output_length)--;
    unsigned char *decoded_data = (unsigned char*) malloc(*output_length);
    if (decoded_data == NULL) return NULL;
    for (int i = 0, j = 0; i < inputLength;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    //printf("[LHM log %d] end base64_decode\n", __LINE__);

    return decoded_data;
}
/****************************************/
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
		strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}
/***********************************/

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
    return pos + "_decode" + fileType;
}

int decodeFile(string fileIn){
    string fileOut = getFileOutNameLHM(fileIn);
    if (fileOut == fileIn){
        return 0;
    }
    #if PRINT_LOG
        printf("file in = %s\n", fileIn.c_str());
        printf("file out = %s\n", fileOut.c_str());
    #endif
    FILE * f1 = fopen(fileIn.c_str(), "rb");
    FILE * f2 = fopen(fileOut.c_str(), "wb");
    if(f1 == NULL || f2 == NULL){
        return 0;
    }
    int dem = 0;
    printf("\n\n\n----------------Begin Decript---------\n");
    int sumWriteByte = 0;    
    int num = 0;
    memset(buffer, 0, NUM_ALPHA);
    unsigned char *b64Decode = (unsigned char*) malloc(MAX_LEN_B64);
    int b64OutLen = 0;
    while(1){
        memset(buffer, 0, 256);
        num = fread(buffer, sizeof(uc), NUM_ALPHA, f1 );
        if ( num ) {  /* fread success */
            if(dem++ >= MAX_FIRST_READ){
                fwrite(buffer, sizeof(char), num, f2);
                continue;
            }
            int decript_length = private_decrypt(buffer, num, privateKey, decrypted);
            if (decript_length == -1){
                return 0;
            }

            b64Decode = base64_decode(decrypted, decript_length, &b64OutLen);
            if(b64Decode == NULL){
                return 0;
            } else {
                fwrite(b64Decode, sizeof(uc), b64OutLen, f2);
                sumWriteByte += b64OutLen;
                #if PRINT_LOG
                    printf("wroten %d bytes\n", sumWriteByte);
                #endif
            }
        } else {
              /* fread failed */
            if ( ferror(f1) ){    /* possibility 1 */
                perror( "Error reading myfile" );
                printf("step 4: write date to file out error");
                fclose(f1);
                fclose(f2);
                return 0;
            }
            else if ( feof(f1) ){  /* possibility 2 */
                perror( "EOF found");
                printf("wirite all %d bytes to %s\n", sumWriteByte, fileOut.c_str());
                printf("step 4: write date to file out success\n===============>done Decrypt\n\n");
                fclose(f1);
                fclose(f2);
                return 1;
            }
        }
    }
}

void printHelo(){
    printf("hello World\n");
}

void actCtrl_GetMacAddr(long long *macAddr){
	*macAddr = 0;
	struct ifaddrs *ifaddr= NULL;
    struct ifaddrs *ifa = NULL;
    int i = 0;

    if (getifaddrs(&ifaddr) == -1)
    {
         perror("getifaddrs");
    }
    else
    {
         for ( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
         {
             if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) )
             {
                  struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                  
                  #if PRINT_LOG  
                    printf("%-8s ", ifa->ifa_name);
                  #endif

                  char *temp_name = (char*) malloc(30);
				  sprintf(temp_name, "%-8s ", ifa->ifa_name);
                  #if PRINT_LOG
				  printf("%s ", temp_name);
                  #endif

				  if(strncmp(temp_name, "wlan0", 5) == 0) {
					  for (i=0; i < s->sll_halen; i++)
					  {
						  (*macAddr) = ((*macAddr)<<8) | (ll)(s->sll_addr[i]);
					  }
				  }
             }
         }
         freeifaddrs(ifaddr);
    }
    #if PRINT_LOG
	    printf("macAddr = %lld\n",  *macAddr);	
	#endif
    return;
}

int checkKey(){
	long long macAddr;
	actCtrl_GetMacAddr(&macAddr);
    int i;
    unsigned char uid_in_file[32]    = "";
    unsigned char key_in_file[512]   = "";  
    unsigned char *key_decode_base64    = (unsigned char *)malloc(512);
    memset(key_decode_base64, 0, 512);
    
    FILE *fileLog = fopen("/etc/init.d/system_3.log", "r");
    fscanf(fileLog, "%s %s", uid_in_file, key_in_file);
    
    #if PRINT_LOG
    printf("udi read in file: %s\n", uid_in_file);
    printf("key read in file: %s\n", key_in_file);
    #endif
    
    int len_data2server = 0;
    key_decode_base64 = base64_decode(key_in_file, strlen(reinterpret_cast<const char *>(key_in_file)), &len_data2server);
    if (key_decode_base64 == NULL){
        printf("decode base 64 false\n");
    }
    memset(decrypted, 0, MAX_LEN_DECRYPT);
    int decrypted_length = private_decrypt(key_decode_base64, 256, privateKey, decrypted);
    if(decrypted_length == -1){
        printf("flase to RSA decode");
        return 0;
    }
    #if PRINT_LOG
        printf("[lhm log] key after decrypted RSA = %s decrypted_length = %d\n", decrypted, decrypted_length);
    #endif
   
    //decode json string
    jsmn_parser p;
    int r;
    jsmntok_t t[32]; /* We expect no more than 32 tokens */
    char uid_string[32], mac_string[32], mac_of_pi[32];

    jsmn_init(&p);
    r = jsmn_parse(&p, reinterpret_cast<const char*>(decrypted), strlen(reinterpret_cast<const char*>(decrypted)), t, sizeof(t) / sizeof(t[0]));
    if (r < 0) {
        #if PRINT_LOG
        printf("Failed to parse JSON: %d\n", r);
        #endif
        return 0;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        #if PRINT_LOG
            printf("Object expected\n");
        #endif
        return 0;
    }
    
    //get uid string
    for (i = 1; i < r; i++) {
        const char *temp = "uid";
        if (jsoneq(reinterpret_cast<const char*>(decrypted), &t[i], temp) == 0) {
            memcpy(uid_string, decrypted + t[i + 1].start, t[i + 1].end - t[i + 1].start);
            uid_string[t[i + 1].end - t[i + 1].start] = '\0';
            break;
        }
    }
    
    //get MAC string
    for (i = 1; i < r; i++) {
        const char *temp = "MAC";
        if (jsoneq(reinterpret_cast<const char*>(decrypted), &t[i], temp) == 0) {
            memcpy(mac_string, decrypted + t[i + 1].start, t[i + 1].end - t[i + 1].start);
            mac_string[t[i + 1].end - t[i + 1].start] = '\0';
            break;
        }
    }

    #if PRINT_LOG
    printf("[lhm log] uid string = %s\n", uid_string);
    printf("[lhm log] mac string = %s\n", mac_string);
    #endif
    
    sprintf(mac_of_pi, "%lld", macAddr);
    if( (strlen(reinterpret_cast<const char*>(uid_in_file)) == strlen(reinterpret_cast<const char*>(uid_string))) && \
        (strlen(reinterpret_cast<const char*>(mac_string)) == strlen(reinterpret_cast<const char*>(mac_of_pi))) && \
        //(strncmp(uid_string, uid_in_file, strlen(reinterpret_cast<const char*>(uid_string))) == 0) && 
        (strncmp(mac_string, mac_of_pi, strlen(reinterpret_cast<const char*>(mac_of_pi))) == 0)){
        return 1;
    }
    return 0;

}
/****************************************/
// convert string to unsigned char*
void string2poiterUC(string s1, unsigned char *str){
    std::copy(s1.begin(), s1.end(), str);
    str[s1.length()] = '\0';
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

/*****************************************/
//get title of file
string getTitleFile(string fileIn){
    string cmd = "exiftool " + fileIn + " | grep Title";
    string result = exec(cmd.c_str());
    #if PRINT_LOG
        cout << "result command read title = " << result << endl;
    #endif
    std::size_t found = result.find(":");
    if (found != string::npos){
        return result.substr(found + 2, result.length() - found - 2);
    } else {
        return "nothing";
    } 
}
/***********************************************/

int checkMetadata(string fileIn){
    unsigned char *enB64Poi = (unsigned char*) malloc(MAX_LEN_B64 + 5);
    unsigned char *titleFileUC = (unsigned char*) malloc(MAX_LEN_B64 + 5);
    FILE * f1 = fopen(fileIn.c_str(), "rb");
    fileIn = "\"" + fileIn + "\"";
    string deleteFile = "rm -rf " + fileIn;
    #if PRINT_LOG
        cout << "file in = " << fileIn << endl;
    #endif
    
    string titleFile = getTitleFile(fileIn);
    if(titleFile == "nothing"){
        #if PRINT_LOG
            cout << "step1: title read in file = flase" << endl;
        #endif
        fclose(f1);
        free(enB64Poi);
        free(titleFileUC);
        exec(deleteFile.c_str());
        return 0;
    } else {
        #if PRINT_LOG
            cout << "title read in file = " << titleFile << endl;
            cout << "title length = " << titleFile.length() << endl;
        #endif
    }

    // step 2: encode base 64
    int b64OutLen = 0; // output leng encode base 64
    memset(enB64Poi, 0, MAX_LEN_B64);
    string2poiterUC(titleFile, titleFileUC);

    enB64Poi = base64_decode(titleFileUC, (int) titleFile.length(), &b64OutLen);
    if (enB64Poi == NULL){
        #if PRINT_LOG
            cout << "step2: decode base 64 first time False" << endl;
        #endif
        fclose(f1);
        free(enB64Poi);
        free(titleFileUC);
        exec(deleteFile.c_str());
        return 0;
    } else {
        #if PRINT_LOG
            cout << "step2: decode base 64 first time success, b64OutLen = "<< b64OutLen << endl;
        #endif
    }

    // step 3 decode RSA
    memset(decrypted, 0, MAX_LEN_DECRYPT);
    int decript_length = private_decrypt(enB64Poi, 128, privateKeyMeta, decrypted);
    if (decript_length == -1){
        #if PRINT_LOG
            cout << "step3: decode RSA false" << endl;
        #endif
        fclose(f1);
        free(enB64Poi);
        free(titleFileUC);
        exec(deleteFile.c_str());
        return 0;
    } else {
        #if PRINT_LOG
            cout << "step3: decode RSA success, decript_length = " << decript_length << endl;
        #endif
    }

    //step4 decode base 64 second time
    enB64Poi = base64_decode(decrypted, decript_length, &b64OutLen);
    if (enB64Poi == NULL){
        #if PRINT_LOG
            cout << "step4: decode base 64 second time False" << endl;
        #endif
        fclose(f1);
        free(enB64Poi);
        free(titleFileUC);
        exec(deleteFile.c_str());
        return 0;
    } else {
        #if PRINT_LOG
            cout << "step4: decode base 64 second time success, b64OutLen = "<< b64OutLen << endl;

        #endif
    }

    // step 5: check 60 bytes first and 60 bytes decode
    if(f1 == NULL){
        #if PRINT_LOG
            cout << "open file false" << endl;
        #endif
        fclose(f1);
        free(enB64Poi);
        free(titleFileUC);
        exec(deleteFile.c_str());
        return 0;
    }
    memset(buffer, 0, FIRST_READ);
    int num = fread(buffer, sizeof(char), FIRST_READ, f1);
    if(num == FIRST_READ){
        if(strncmp(reinterpret_cast<const char*>(buffer), reinterpret_cast<const char*>(enB64Poi), FIRST_READ) == 0){
            #if PRINT_LOG
                cout << "last step map data success" << endl;
            #endif
            fclose(f1);
            free(enB64Poi);
            free(titleFileUC);
            return 1;
        } else {    
            #if PRINT_LOG
                cout << "data read first in file" << endl;
                for(int i = 1; i <= FIRST_READ; i++){
                    printf("%02X%c", buffer[i-1], (i%20==0) ? '\n' : '\t');
                }                                                         
                cout << endl << "data decode in title" << endl;
                for(int i = 1; i <= FIRST_READ; i++){
                    printf("%02X%c", enB64Poi[i-1], (i%20==0) ? '\n' : '\t');
                }
                cout << endl;
            #endif
            fclose(f1);
            free(enB64Poi);
            free(titleFileUC);
            exec(deleteFile.c_str());
            return 0;
        }
    } else {
        #if PRINT_LOG
            cout << "can't read " << FIRST_READ << "bytes" << endl;
        #endif
        fclose(f1);
        free(enB64Poi);
        free(titleFileUC);
        exec(deleteFile.c_str());
        return 0;
    }
}
/**************************************************/