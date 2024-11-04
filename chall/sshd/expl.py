#!/usr/bin/env python3
import sys
from pwn import *

elf = ELF("./loader")
context.update(binary=elf, log_level="DEBUG")
p = gdb.debug([elf.path], gdbscript='''
    break *main+198
''')
# hexdump 




p.interactive()