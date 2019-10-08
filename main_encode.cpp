#include <iostream>
#include <string>
#include "encode.h"
using namespace std;
int main(int argc, char *argv[]){
        cout << "Encode metadata simple example" << endl; 
        if (argc != 2){
                cout << "input expect only path to file, fucking idiot" << endl;
                return 0;
        }
        string fileName = argv[1];
        if(encodeMetaData(fileName)){
            cout << "encode success" << endl;
        } else {
            cout << "encode flase" << endl;
        }
        return 0;
}