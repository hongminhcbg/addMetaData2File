#ifndef _CHECKCOPPYRIGHT_H_
#define _CHECKCOPPYRIGHT_H_
#include <iostream>
    int decodeFile(std::string path);
    std::string getFileOutNameLHM(std::string fileIn);
    int checkKey();
    void printHelo();
    int checkMetadata(std::string fileIn);
#endif