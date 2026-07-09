from pwnlib.replacements import sleep
from pwn import *
from tools.uboot_shell import open_uboot_shell

print("Waiting for U-Boot Shell...")
p = open_uboot_shell()
print("Loading Firmware...")
sleep(0.3)
p.sendline(b"tftp 0x81000000 new-firmware.bin")
p.recvuntil(b"done")
sleep(0.3)
p.sendline(b"erase 0x9f020000 +3c0000")
p.recvuntil(b"Erased 60 sectors")
sleep(0.3)
p.sendline(b"cp.b 0x81000000 0x9f020000 3c0000")
p.recvuntil(b"done")
sleep(0.3)
print("Rebooting...")
p.sendline(b"reset")
p.interactive()