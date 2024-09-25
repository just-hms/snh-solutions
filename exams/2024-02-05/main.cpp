#include <iostream>

int main(){
    unsigned long a =0x0000630a40aab7d6;
    char * b= (char*)&a;
    printf("%s\n", b);
}