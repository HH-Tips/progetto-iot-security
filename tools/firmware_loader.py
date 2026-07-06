from pwn import *
from tools.uboot_shell import open_uboot_shell

print("Waiting for U-Boot Shell...")
p = open_uboot_shell()
print("Loading Firmware...")
sleep(0.3)
p.sendline(b"tftp 0x81000000 new-firmware.bin")
p.recvuntil(b"done")
print("Rebooting...")
p.sendline(b"bootm 0x81000000")
p.interactive()