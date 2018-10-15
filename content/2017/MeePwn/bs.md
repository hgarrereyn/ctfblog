---
title: "MeePwn 2017 - bs (100pt)"
description: "Buffer overflow leading to multi-part GOT overwrite"
date: 2017-07-16
tags: ["exploit"]
---

# bs (100pt)

**`Exploitation`**

**Files:**

* [bs](/code/2017/MeePwn/bs)
* Exploit script: [solveBS.py](/code/2017/MeePwn/solveBS.py)

# Summary

This challenge was really fun because I got to use ROP gadgets and GOT overwrites in the same exploit. The program itself allowed the user to enter a sequence of numbers which were sorted with a quick sort algorithm. Then the user could specify a target number and the program used a binary search to find the target. If it was found, the user could edit the values at that location and each location after it.

The main vulnerability occured during the binary search portion. If the user entered enough numbers, the buffer pointer could jump before the start of the buffer and into the GOT table. This allowed an attacker to overwrite multiple stdlib functions in such a way as to simulate the function call `system('sh')` and spawn a shell.

# Part 1 - Root Check

The program starts by calling a login subroutine that reads 16 bytes from `/dev/urandom` and compares it to bytes read from stdin. If they match, the subroutine returns zero. Otherwise, the user is allowed to enter a user id via `scanf(%d, &val)`. The program exits if the supplied id is equal to zero or greater than 256.

A second subroutine takes that value and sets an `is_root` bit if the value is zero. However, it only checks the lowest two bytes. Therefore, entering a signed value such as: `-2147418112` (`0xFFFF0000`) is enough to fool the check and set the `is_root` bit to 1.

# Part 2 - GOT Access

Once the `is_root` bit is set, the user is able to enter more than 32 numbers (which is required to obtain the buffer error). This part was a bit of trial and error. I used gdb to read memory near the GOT table and figure out which memory addresses corresponded to which buffer addresses. In the final exploit, I ended up sending 121 numbers which allowed me to jump to a consistent place in the GOT table.

Then I was able to iterate through the GOT table and overwrite certain values. The tricky part was figuring out how to craft a shell using only sequential GOT overwrites.

The GOT table is ordered like this:

```x86asm
             read@GOT:
0804b00c         dd         0x0804c000
             printf@GOT:
0804b010         dd         0x0804c004
             memcmp@GOT:
0804b014         dd         0x0804c008
             puts@GOT:
0804b018         dd         0x0804c00c
             exit@GOT:
0804b01c         dd         0x0804c014
             open@GOT:
0804b020         dd         0x0804c018
             __libc_start_main@GOT:
0804b024         dd         0x0804c01c
             setvbuf@GOT:
0804b028         dd         0x0804c020
             __isoc99_scanf@GOT:
0804b02c         dd         0x0804c024
```

# Part 3 - Vulnerable Call

In the entire program, the only libc call on a user suplied buffer is in the login subroutine where the program checks `/dev/urandom` bytes against stdin bytes:

```x86asm
             login:
080485cb         push       ebp                                                 ; CODE XREF=main2+47
080485cc         mov        ebp, esp
080485ce         sub        esp, 0x38
080485d1         sub        esp, 0x8
080485d4         push       0x0                                                 ; argument "oflag" for method j_open
080485d6         push       0x8048c50                                           ; "/dev/urandom", argument "path" for method j_open
080485db         call       j_open
080485e0         add        esp, 0x10
080485e3         mov        dword [ebp+var_C], eax
080485e6         sub        esp, 0x4
080485e9         push       0x10                                                ; argument "nbyte" for method j_read
080485eb         lea        eax, dword [ebp+var_1C]
080485ee         push       eax                                                 ; argument "buf" for method j_read
080485ef         push       dword [ebp+var_C]                                   ; argument "fildes" for method j_read
080485f2         call       j_read
080485f7         add        esp, 0x10
080485fa         sub        esp, 0xc
080485fd         push       0x8048c5d                                           ; "Enter your password:", argument "s" for method j_puts
08048602         call       j_puts
08048607         add        esp, 0x10
0804860a         sub        esp, 0x4
0804860d         push       0x10                                                ; argument "nbyte" for method j_read
0804860f         lea        eax, dword [ebp+var_2C]
08048612         push       eax                                                 ; argument "buf" for method j_read
08048613         push       0x0                                                 ; argument "fildes" for method j_read
08048615         call       j_read
0804861a         add        esp, 0x10
0804861d         sub        esp, 0x4
08048620         push       0x10                                                ; argument "n" for method j_memcmp
08048622         lea        eax, dword [ebp+var_2C]
08048625         push       eax                                                 ; argument "s2" for method j_memcmp
08048626         lea        eax, dword [ebp+var_1C]
08048629         push       eax                                                 ; argument "s1" for method j_memcmp
0804862a         call       j_memcmp
0804862f         add        esp, 0x10
08048632         test       eax, ea
```

The problem is that the user-supplied buffer is the *second* argument to `memcmp` and the command string to `system` must be the first argument. So overwriting `memcmp@GOT` with `system@GOT` would turn this:

```c
memcmp(&random_bytes, &user_bytes, 0x10);
```

into this:

```c
system(&random_bytes); // ignores user_bytes
```

# Part 4 - Control *Both* Buffers

If we can somehow control the data in the first buffer, we can call `system` with our own string. 

Currently, the random bytes are read like this:

```c
char rand_bytes[16];
char user_bytes[16];

int file = open("/dev/urandom", 0);
read(file, &rand_bytes, 16);

read(0, &user_bytes, 16);
```

The solution is to overwrite `open@GOT` with a gadget that returns zero. This way, the following `read` call will use a file descriptor of zero which indicates stdin.

I used ROPgadget to find a `xor eax; ret` gadget. This effectively turned the control flow into:

```c
char rand_bytes[16];
char user_bytes[16];

int file = 0;
read(file, &rand_bytes, 16);

read(0, &user_bytes, 16);
```

Then we are able to pass the bytes `sh` and spawn a shell.

# Part 5 - Launch Exploit

The last step is to jump back to the login procedure once we have overwritten all the values.

I did this by replacing `scanf@GOT` with the address of `<login>`.

*Even though `scanf` is used in the section of code that actually writes buffer values, it is the last entry in the GOT table and therefore we can overwrite this last without breaking things.*

# Full Exploit

1. Trick root check with a signed negative number
2. Exploit incorrect logic to get a GOT table pointer
3. Overwrite GOT addresses:
  * `memcmp` -> `system`
  * `open` -> `xor eax; ret` gadget
  * `scanf` -> `<login>`
4. Enter `sh` bytes to spawn shell