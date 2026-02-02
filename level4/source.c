#include <stdio.h>
#include <stdlib.h>

extern unsigned int m = 0;

void p(char *buff) {
	printf(buff);
	return;
}

void v() {
	char 	buff[520];

	fgets(buff, 512, stdin);
	p(buff);
	if (m != 16930116)
		return;
	system("/bin/cat /home/user/level5/.pass");
	return;
}

int main() {
	v();
	return (0);
}