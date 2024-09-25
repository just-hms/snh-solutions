# GDB

```
b * fun+22
disass fun
sudo gdb -p <`pidof binary` | pid>
got
ni
c
```

leak the canary position

```
set follow-fork-mode child
b*child
// ni fino a [rbp-8]
p $rbp-8 // leggi [rbp-8] per trovare dove sta il canary
// smasha con cyclic
x/s 0x7ffd071286a8 // vedi cosa c'è dentro
// clyclic -l delle prime cose (ne bastano 4)
```
