#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    int value = atoi(argv[1]);
	if (value == 423) {
		char *str = strdup("/bin/sh");
		gid_t gid = getegid();
		uid_t uid = geteuid();
		setresgid(gid, gid, gid);
		setresuid(uid, uid, uid);
		execv(str, NULL);
	} else {
		fwrite("No !\n", 1, 5, stderr);
	}
    return 0;
}