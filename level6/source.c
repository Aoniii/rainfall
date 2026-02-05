#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int n()
{
    return system("/bin/cat /home/user/level7/.pass");
}

unsigned int m()
{
    return puts("Nope");
}

int main() {
	void*	ptr1;
	void*	ptr2;
	char	buff;

    ptr1 = malloc(64);
    ptr2 = malloc(4);
    ptr2 = &m;
    strcpy(ptr1, buff);
	return (ptr2);
}