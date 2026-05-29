#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int uuencode(char *src_file, char *dst_buff){
    char cmd[50]="";
    sprintf(cmd, "uuencode %s %s > temp", src_file, src_file);
    system(cmd);
    FILE *fd = fopen("temp", "r");
    char buff[200];
    strcpy(dst_buff, "");
    while(fscanf(fd, "%s", buff)!=EOF){
        printf("%s", buff);
        strcat(dst_buff, buff);
        strcat(dst_buff, "\n");
        printf("%s", dst_buff);
    }
    system("rm temp");
}


int main(int argc, char** argv){
    char buff[102400];
    uuencode("logo.jpg", buff);
    printf("%s", buff);
    return 0;
}
