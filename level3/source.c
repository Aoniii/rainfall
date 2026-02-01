#include <stdio.h>
#include <stdlib.h>

extern unsigned int m = 0;

void v() {
	char 	buff[520];

	fgets(buff, 512, stdin);
	printf(buff);
	if (m != 64)
		return;
	fwrite("Wait what?!\n", 1, 12, stdout);
	system("/bin/sh");
	return;
}

int main() {
	v();
	return (0);
}