SET file="main.cpp" "main_encode.cpp" "encode.h" "encode.cpp" "Makefile" "jsmn.cpp" "jsmn.h" "checkCopyright.h" "checkCopyright.cpp" "main_CCR.cpp"
rem "C:\Users\Administrator\Desktop\pscp\pscp.exe" -pw 1 "main.cpp" "main_encode.cpp" "encode.h" "encode.cpp" "Makefile" lhm@192.168.126.128:/home/lhm/Desktop/addMetaData
"C:\Users\Administrator\Desktop\pscp\pscp.exe" -pw "MQ@123456789" %file% pi@192.168.6.69:/home/pi/addMetaData2File
