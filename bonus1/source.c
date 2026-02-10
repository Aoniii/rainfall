#include <string.h>

int main(int argc, char **argv) {
    char buffer[40];
    int num;
	
	num = atoi(argv[1]);
    if (num > 9)
        return 1;
    memcpy(buffer, argv[2], num * 4);
    if (num != 1464814662)
        return 0;
	execl("/bin/sh", "sh", NULL);
    return 0;
}
