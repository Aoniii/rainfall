#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    char	password[66];
	char	buffer[65];
    FILE	*fp;

    fp = fopen("/home/user/end/.pass", "r");

	memset(password, 0, 132);

	if (fp && argc == 2) {
		fread(password, 1, 66, fp);
		password[atoi(argv[1])] = '\0';
		fread(buffer, 1, 65, fp);
		fclose(fp);
		if (!strcmp(password, argv[1]))
			execl("/bin/sh", "sh");
		else
			puts(buffer);
		return 0;
	}
    return -1;
}
