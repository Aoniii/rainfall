#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct struct_ {
    unsigned int field_0;
    void* field_4;
} struct_;

extern char c = 0;

void m() {
    printf("%s - %d\n", &c, time(NULL));
	return;
}

int main(int argc, char **argv) {
	struct_ *ptr;
    struct_ *p;

    p = malloc(8);
    p->field_0 = 1;
    p->field_4 = malloc(8);
    ptr = malloc(8);
    ptr->field_0 = 2;
    ptr->field_4 = malloc(8);
    strcpy(p->field_4, argv[1]);
    strcpy(ptr->field_4, argv[2]);
    fgets(&c, 68, fopen("/home/user/level8/.pass", "r"));
    puts("~~");
	return (0);
}