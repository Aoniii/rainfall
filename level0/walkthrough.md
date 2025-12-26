# Level0

We have an executable file.

```
$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```

It segfaults without an argument, and it seems that a value is required.

```
$ ./level0
Segmentation fault (core dumped)
$ ./level0 42
No !
```

Let's use gdb to disassemble the main function and understand it.

```
$ gdb --args ./level0 42
disas main
...
0x08048ed4 <+20>:    call   0x8049710 <atoi>
0x08048ed9 <+25>:    cmp    $0x1a7,%eax
...
```

The main function calls atoi and expects argv[1] to be equal to 423 in order to continue.
</br>
We can also see calls to strdup, getegid, geteuid, setresgid, setresuid, execv, fwrite.

```
$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```