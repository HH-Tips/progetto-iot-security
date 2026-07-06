from pwn import *

def open_uboot_shell(interactive: bool = False, verbose: bool = False) -> process:
    while True:
        try:
            p = process(["picocom", "-b", "115200", "/dev/ttyUSB0"])

            out = p.recvuntil(b"Autobooting in 1 seconds")
            if verbose:
                print(out.decode())
            p.sendline(b"tpl")
            if interactive:
                p.interactive()
            return p
        except KeyboardInterrupt:
            return
        except:
            pass

if __name__ == "__main__":
    open_uboot_shell(interactive=True)
