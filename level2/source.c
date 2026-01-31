#include <stdio.h>
#include <stdlib.h>

void p() {
	int 	retaddr;
	char 	buff[76];

	fflush(stdout);
	gets(buf);
	retaddr = *(int *)(buf + 76);
	if ((retaddr & 0xb0000000) == 0xb0000000) {
		printf("(%p)\n",(void*)retaddr);
		exit(1);
	}
	puts(buf);
	strdup(buf);
	return;
}

int main() {
	p();
	return (0);
}