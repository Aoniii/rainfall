#include <stdio.h>
#include <stdlib.h>

void p() {
	int 	retaddr;
	char 	buff[76];

	fflush(stdout);
	gets(buff);
	retaddr = *(int *)(buff + 76);
	if ((retaddr & 0xb0000000) == 0xb0000000) {
		printf("(%p)\n",(void*)retaddr);
		exit(1);
	}
	puts(buff);
	strdup(buff);
	return;
}

int main() {
	p();
	return (0);
}