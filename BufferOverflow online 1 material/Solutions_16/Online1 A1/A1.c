
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
40 308 528
int foo(char *str)
{
    int arr[40];
    char buffer[308];

    /* The following statement has a buffer overflow problem */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char str[528];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), <param_3>, badfile);
    foo(str);

    printf("Try Again\n");
    return 1;
}

