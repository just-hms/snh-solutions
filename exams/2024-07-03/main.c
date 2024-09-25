#include <stdio.h>
#include <limits.h>


int main(){
    int a = INT_MAX;
    int b = INT_MAX; 
    int c = a+b;

    printf("%d\n", a);
    printf("%d\n", b);
    printf("%ld\n", SIZE_MAX - c + 1);

}
