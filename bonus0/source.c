#include <stdio.h>
#include <string.h>

void p(char *s1, char *s2) {
    char buffer[4096];

    puts(s2);
    read(0, buffer, 4096);
    *strchr(&buffer, '\n') = 0;
    strncpy(s1, &buffer, 20);
    return;
}

void pp(char *buffer) {
    char s1[20];
    char s2[20];

    p(s1, " - ");
    p(s2, " - ");
	strcpy(buffer, s1);
    
	char *tmp = buffer;
	while (*tmp)
		tmp++;
	*tmp= ' ';

    strcat(buffer, s2);
    return;
}

int main(void) {
    char buffer[42];

    pp(buffer);
    puts(buffer);
    return 0;
}
