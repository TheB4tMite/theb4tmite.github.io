---
layout: post
date: 2024-08-30 17:35:00 +0530
title: TFC CTF 2024 - Guard the Bypass
categories: Stack Writeup
tags: Writeup
description: Canary Bypass via Master Canary Overwrite
media_subpath: /assets/media/tfctf-2024-guard-the-bypass/
---

## Challenge Description

```Guard this cookie.```

Handout Files:
- _Dockerfile_
- _guard_ - ELF file 
- _ld-2.35.so_
- _libc.so.6_

## Initial Analysis

`checksec` reveals that the binary has the following protections:

![img-description](checksec_guard.png){: w="275" .normal}

Since its Partial RELRO, we can overwrite `.got.plt` to make our exploit.

Let\'s disassemble the binary and see what it holds...

![img-description](main_disass.png){: w="600" .normal}  

We can see that the program allows us to specify a certain length and then creates a thread to run the game function.

![img-description](game_disass.png){: w="550" .normal}

The game function calls read with our len input as the 3rd argument which allows us to control the number of bytes being read into the buffer. The buffer has a size of 5. Clearly, there is a buffer overflow here.

## Approach

### Canary Bypass

Now, you might consider reading more bytes into the buffer and executing a ROP chain. However, the binary has canary protection. A canary is a value on the stack that is placed before the return address. If the value is overwritten then the program exits by calling `__stack_chk_fail()`. 

In this case, we have no way to leak the canary, however, since the process is running in a separate thread we can overwrite the canary. 

 When new processes are created the program keeps track of the values new threads may need by storing them in the Thread-Local Storage (TLS). The master canary is stored in the TLS. We can see that it is accessed using the `fsbase + 0x28`. When a new process is created the main process canary is copied to the thread stack. The thread stack is adjacent to the TLS. This allows us to overflow into the TLS and overwrite the master canary.

Once we overwrite both the master canary and thread canary we can modify the return address. 

The thread stack canary is placed before `rbp` so our payload to overwrite it will look something like this:

`padding + fake_canary + rbp_value`

Once we overwrite the thread stack canary we also need to ensure that the master canary in the TLS is overwritten with the same fake canary value. To do so we need to overwrite the stack up until the master canary value. This would however result in a segmentation fault since we\'ve corrupted a required address.

![img-description](invalid_address.png){: w="600" .normal}

If we check the location of the address on the stack we can see that it we\'ve corrupted a writeable address on the stack with our padding.

![img-description](caaudaau.png){: w="500" .normal} 
_Where we corrupted_

![img-description](heap_address.png){: w="500" .normal}
_What we corrupted_

We can simply replace this value with another writeable address. I used an address in the `bss` but you can use any other writeable address. Our corrected payload should look like this:

`padding + fake_canary + rbp_value + padding + write_addr + padding + fake_canary`

### Obtaining leaks

Now we need to obtain a libc leak to call system, we can do so by executing a ret2plt attack.

We can call `puts@plt` with the GOT address of `puts` as argument in order to leak the libc address of `puts`. We also need to call the `game` function again to rop again and call `system`.

Our payload should look something like this: 

`padding + fake_canary + rbp_value + pop_rdi + puts_got + puts_plt + game`

Now that we have bypassed the canary and obtained a libc leak, we can call system and cat the flag.

### Final Exploit

You can find the challenge files and my exploit script [here](https://github.com/TheB4tMite/CTF-Writeups/tree/main/TFC_CTF_2024/Guard_the_bypass)
