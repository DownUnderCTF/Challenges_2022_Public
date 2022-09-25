#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(1000);
    FILE *fp = fopen("/home/ghostccamm/flag.txt", "r");
    char buffer[255];
    if (fp == NULL) {
        exit(1);
    }

    fgets(buffer, 255, fp);
    printf("%s\n", buffer);
    fclose(fp);
}