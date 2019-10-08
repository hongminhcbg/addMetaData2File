#include <stdio.h>
#include <iostream>
#include <string>
#include "checkCopyright.h"
using namespace std;
int main(int argc, char *argv[]){
    cout << "Read metadata simple example" << endl; 
    if (argc != 2){
            cout << "input expect only path to file, fucking idiot" << endl;
            return 0;
    }
    string fileName = argv[1];
    if(checkMetadata(fileName)){
        cout << "copyright MQ ICT SOLUTIONS success" << endl;
    } else {
        cout << "copyright MQ ICT SOLUTIONS flase" << endl;
    }        
}