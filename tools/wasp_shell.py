from pwn import *

while True:
    try:
        p = process(["picocom", "-b", "115200", "/dev/ttyUSB0"])

        p.recvuntil(b"Autobooting in 1 seconds")
        p.sendline(b"tpl")
        p.interactive()
        break
    except:
        pass