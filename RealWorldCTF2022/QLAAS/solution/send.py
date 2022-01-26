#!/usr/bin/env python3

import base64
from pwn import *


if __name__ == '__main__':
    f = open("./xpl", "rb")
    data = f.read()
    f.close()

    b64 = base64.b64encode(data)

    #p = remote("47.242.149.197", 7600)
    p = process(["python3", "./main.py"])

    p.sendline(b64)
    p.interactive()
