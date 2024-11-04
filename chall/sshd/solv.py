#!/usr/bin/env python3
from pwn import *
import binascii
from Crypto.Cipher import ChaCha20

core = Coredump('./sshd.core.93794.0.0.11.1725917676')

log.success(f"[Pharse 1]: Analysis encrypt_shellcode in liblzma.so.5.4.1 !")

for reg, value in core.registers.items():
    log.info(f"{reg}: {hex(value)}")

log.info(f'Searched for the keyword "expand 32-byte k" in the function `sub_93F0()` of the library `liblzma.so.5.4.1`, and identified that the algorithm used to decrypt the shellcode is "chacha20".')
data = core.read(core.rsi, core.rdi)
key = data[4:4+32]
nonce = data[36:36+12]
log.info(f"Data in register [RSI] (length {len(data)}) -> {data}")
log.info(f"Key (length {len(key)}) -> {key}")
log.info(f"Nonce (length {len(nonce)}) -> {nonce}")

key_hex = ' '.join(f'{b:02x}' for b in key)
nonce_hex = ' '.join(f'{b:02x}' for b in nonce)
log.info(f"Key (hex) -> {key_hex}")
log.info(f"Nonce (hex) -> {nonce_hex}")

# for mapping in core.mappings:
#     print(mapping)
# strings = core.strings(core.rsp)
# print(strings)
# print(core.stack)

#######################################################################################################
# Dump encrypted shellcode from liblzma.so.5.4.1
start_address = 0x23960
length_shellcode = 3990

with open('liblzma.so.5.4.1', 'rb') as lib_file:
    lib_file.seek(start_address)
    encrypted_data = lib_file.read(length_shellcode)
    
    with open('encrypted_shellcode.bin', 'wb') as f:
        f.write(encrypted_data)
        log.success("Success: Dumped encrypted shellcode!")

cipher = ChaCha20.new(key=key, nonce=nonce)
decrypted_shellcode = cipher.decrypt(encrypted_data)
with open('decrypted_shellcode.bin', 'wb') as f:
    f.write(decrypted_shellcode)
    log.success("Success: Decrypted shellcode to file decrypted_shellcode.bin!")



########################################################################################################
log.success(f"[Pharse 2]: Analysis shellcode in liblzma.so.5.4.1 use \"loader.c\" !")
log.success(f"Setup argv in shellcode.")
registers_to_argv_loader = ['rbx', 'rsi', 'rdi', 'r12']
for reg in registers_to_argv_loader:
    if reg in core.registers:
        value = core.registers[reg]
        log.info(f"{reg}: {hex(value)}")
    else:
        log.warning(f"{reg} not found in core dump.")
        

rbp_test = core.rsp - 0x8
addr_filename_shellcode = rbp_test - 0x1278
rbp_true = addr_filename_shellcode + 0x1248

key_32_addr = rbp_true - 0x1278
nonce_16_addr = rbp_true - 0x1258
filename_256_addr = rbp_true - 0x1248
buf_4224_addr = rbp_true - 0x1148

data1 = (core.read(key_32_addr, 32)).split(b'\x00', 1)[0] + b'\x00'
hex1 = ' '.join(f'{b:02x}' for b in data1)
converted1 = ''.join(f'\\x{byte}' for byte in hex1.split())

data2 = (core.read(nonce_16_addr, 16)).split(b'\x00', 1)[0]  + b'\x00'
hex2 = ' '.join(f'{b:02x}' for b in data2)
converted2 = ''.join(f'\\x{byte}' for byte in hex2.split())

data3 = (core.read(filename_256_addr, 256)).split(b'\x00', 1)[0] + b'\x00'
hex3 = ' '.join(f'{b:02x}' for b in data3)
converted3 = ''.join(f'\\x{byte}' for byte in hex3.split())

data4 = (core.read(buf_4224_addr, 0x80)).split(b'\x00', 1)[0] + b'\x00'
hex4 = ' '.join(f'{b:02x}' for b in data4)
converted4 = ''.join(f'\\x{byte}' for byte in hex4.split())

size = len(data3) - 1
size_4 = len(data4) - 1

log.info(f"key_32_addr       : {hex(key_32_addr)} - set {{char [{len(data1)}]}}(address) = \"{converted1}\"")
log.info(f"nonce_16_addr     : {hex(nonce_16_addr)} - set {{char [{len(data2)}]}}(address) = \"{converted2}\"")
log.info(f"filename_256_addr : {hex(filename_256_addr)} - set {{char [{len(data3)}]}}(address) = \"{converted3}\"")
log.info(f"buf_4224_addr     : {hex(buf_4224_addr)} - set {{char [{len(data4)}]}}(address) = \"{converted4}\"")

log.info(f'size   - set {{char [2]}}(address) = "\\x{hex(size)[-2:]}\x00"')
log.info(f'size_4 - set {{char [2]}}(address) = "\\x{hex(size_4)[-2:]}\x00"')

