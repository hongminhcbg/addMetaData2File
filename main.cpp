#include <stdio.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <fstream>

#define FILE_TEXT_OUT "/tmp/out.txt"
// read metadata command
// ffmpeg -i video_encode.mp4 -f ffmetadata out.txt -y
// add title
// ffmpeg -i video.mp4 -strict -2 -metadata title="Movie Title" video2.mp4
using namespace std;

std::string exec(const char* cmd) {
    char buffer[128];
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

std::string readFileTextOut(){
        //FILE *f1 = fopen(FILE_TEXT_OUT, "r");
        std::string containTitle = "title=";
        std::ifstream input(FILE_TEXT_OUT);
        for( std::string line; getline(input, line );){
                std::size_t found = line.find(containTitle);
                if ( found == 0) {
                        cout << found << line << endl;
                        // get title
                        return line.substr(6, line.length() - 6);
                }
        }
        return "nothing";
}

void readMetadata(string fileName){
        string cmd = "ffmpeg -i " + fileName + " -f ffmetadata " + FILE_TEXT_OUT + " -y";
        string result = exec(cmd.c_str());
        cout << "result = " << result << endl;
        cout << readFileTextOut() << endl;
}
int main(int argc, char *argv[])
{
        cout << "Read metadata simple example" << endl; 
        if (argc != 2){
                cout << "input expect only path to file, fucking idiot" << endl;
                return 0;
        }
        string fileName = argv[1];
        readMetadata(fileName);
        return 0;
}