#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
	char input[128];
	void *auth = NULL;
	void *service = NULL;

    while (1) {
		printf("%p, %p \n", auth, service);
		if (!fgets(input, 128, stdin))
			break;
		if (!memcmp(input, "auth ", 5)) {
			auth = malloc(4);
			if (strlen(input) <= 30)
				strcpy(auth, input);
		}
		if (!memcmp(input, "reset", 5))
			free(auth);
		if (!memcmp(input, "service", 6))
			service = strdup(input);
		if (!memcmp(input, "login", 5)) {
			if ((auth + 32) != 0)
				system("/bin/sh");
			else
				fwrite("Password:\n", 1, 10, stdout);
		}
	}
	return (0);
}
