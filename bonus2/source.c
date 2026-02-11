#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int language = 0;

void greetuser(char *str)
{
    char buffer[88];

    if (language == 1)
    {
        strncpy(buffer, "Hyvää päivää ", 13);
    }
    else if (language == 2)
    {
        strncpy(buffer, "Goedemiddag! ", 13);
    }
    else if (!language)
    {
        strncpy(buffer, "Hello ", 6);
    }
    strcat(buffer, str);
    puts(buffer);
    return;
}

int main(int argc, char **argv) {
	char	v1[40];
    char	v2[32];
    char	combined[76];

    if (argc != 3)
        return 1;

	memset(v1, 0, 76);
    strncpy(v1, argv[1], 40);
    strncpy(v2, argv[2], 32);

    char *lang = getenv("LANG");
    if (lang) {
        if (!memcmp(lang, "fi", 2))
            language = 1;
        else if (!memcmp(lang, "nl", 2))
            language = 2;
    }

    memcpy(combined, v1, 76);
	greetuser(combined);
    return 0;
}