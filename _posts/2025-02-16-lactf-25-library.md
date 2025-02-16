---
layout: post
date: 2025-02-16 10:00:00 +0530
title: LA CTF 2025 - Library
categories: Heap
description: House of Einherjar to Ret2System
media_subpath: /assets/media/lactf-2025-library/
---

## Introduction
This challenge was my first solve of a heap challenge involving House of Einherjar, though I wasn't able to make much progress past the leaks during the CTF I managed to solve it afterwards. It is possible to solve this challenge using FSOP which was the author's solution, however I wanted to make it slightly harder for myself so I went with the return addresss overwrite solution.

## Challenge Description

`Read any file on the filesystem`

Handout Files:
- _library_
- _Dockerfile_
- _libc.so.6_
- _ld-linux-x86-64.so.2_

## Initial Analysis

`checksec` reveals that the binary has all protections enabled and the libc version of the file is 2.39 which means the libc GOT is no longer writeable.

```bash
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
```bash
strings libc.so.6 | grep "GNU C"
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.2) stable release version 2.39.
Compiled by GNU CC version 13.2.0.
```

We are given the source file for the challenge saving us time spent reversing the binary.

Looking at the `order_book` function we see that it allocates a chunk of the size of the Book struct.
```c
struct Book {
	int id;
	char name[0x10];
	char *review;
};
```
The id is set and incremented each time using the `book_cnt` global variable.
It then asks us for the name of the book which reads 0xf bytes into the name buffer.

Note that although the `MAX_BOOKS` constant has been set to 64 we can still allocate as many books as we want.

Next we look at the `read_book` function. Here, we can see that it only allows us to read books from 0-64.

It uses `open` to open the file using the book namne we give as argument by dereferencing the Book struct pointers from the `library` array which is in the bss.

When it comes to how the book is read out we see 2 paths...
```c
if (*(long*)settings->profile != 0x1a1) {
    off_t off = 0;
    sendfile(1, fd, &off, settings->comprehension);
} else {
    char *buf = malloc(settings->comprehension);
    int cnt = read(fd, buf, settings->comprehension);
    write(1, buf, cnt);
    free(buf);
}
```
If `settings->profile` is set to `0x1a1` the program uses sendfile to send `settings->comprehension` amount of bytes to stdout. Otherwise, it mallocs a chunk of `settings->comprehension` bytes and reads the same amount into the chunk. Then it writes the chunk contents to stdout and frees the chunk.

The `review_book` function allows us to allocate and write to a chunk upto size 0x10000. It again checks whether the book ID is within limits.
If `book->review` is not set it allocates a new chunk after asking for size and reads into it.
```c
book->review = malloc(len);
printf("enter review: ");
book->review[read(0, book->review, len)] = 0;
```
We see that it sets end of the content to NULL using the number of bytes read as an index, this causes an off-by-one null byte write into the size of the next chunk.

In the `manage_account` function it allows us to update the settings profile, add a library card or recover settings through RAIS.

Reading into bio, allows us to write 16 bytes into `settings->profile+8`.

Adding a library card allows us to write upto 0x100 bytes by allocating a chunk of size of the entered bytes.

Recovering the settings through RAIS allocates a chunk of size 0x69 and resets settings to the original pointer if it ever gets overwritten.

In the main section of the program we can see that the settings chunk is allocated and rais1 and rais2 are initialised to the settings chunk pointer.

`settings->comprehension` is set to 12 bytes.

## Approach

### Obtaining Leaks

The first thing we need is a way to leak heap and libc base addresses. Since we can read any file on the filesystem this is possible via reading `/proc/self/maps` which contains the mappings for each segment of the current process.

We are however hindered by the fact that we can read only 12 bytes of any file we open. This can be bypassed by overwriting `settings->comprehension` of the `settings` struct.

Since the `order_book` function doesn't check for how many books it reads it allows us to go out of bounds of the library array and overwrite the `settings` pointer with a book we order.

```c
struct Settings {
	uint64_t id;
	char profile[0x18];
	char *card;
	uint16_t comprehension;
};
```

Ordering 63 books overwrites upto the settings chunk, the next chunk after that needs to contain a 4 byte value to overwrite the last 4 bytes of the id field followed by `\xa1\x01`.

![img-description](settings.png)
_settings chunk after writes_

Now we have to bypass the size restriciton on our read, this can be done by allocating a chunk of whatever size we want to set as the read size. Due to the nature of the struct, the size header of our allocated chunk aligns with the `comprehension` variable. I've used an 0xff70 sized chunk, allowing me to read upto 0xff81 bytes.

Now that we have unrestricted read size, we can go ahead and read `/proc/self/maps` and get the leaks we want.

At this point since we have the libc and heap leak it is possible to proceed with House of Einherjar and do FSOP, however for the purpose of this writeup I have to obtain a reliable stack leak.

One detail to note is that the `/proc/self/maps` file is slightly different on remote and thus I had adjust my leaks for the exploit to run properly on remote.

### Getting Stack Leak

To get a reliable stack leak, we need to read the `environ` symbol in libc which points to the environment symbols on the stack. This means, we need some method to read from an arbitrary address.

The only chunks the program allows us to read are the chunks in the library array. Using this knowledge, we have to be able to allocate a chunk near the library array and modify one of the pointers to point near the `environ` symbol.

Using the off-by-one in the review book function we can use House of Einherjar to obtain a chunk at the library array.

House of Einherjar exploits the chunk consolidation functionality by setting the `PREV_SIZE` field and the `PREV_INUSE` bit.

The idea is to write the `PREV_SIZE` field with the size of the fake chunk we want such that the victim chunk (the chunk who's `PREV_INUSE` bit we set to 0) minus the prev size we set points to the fake chunk. Once this is done, the victim chunk is freed which triggers consolidation and gives us a fake freed chunk at the location we want.

![img-description](hoe.png)

We leverage this to get overlapping chunks over the chunk we use to write the prev size field and for the null-byte overflow.

Before we can obtain the overlapping chunks we need to fill up the tcache free list for the size of our victim chunk so that it triggers consolidation when it is freed.

After having obtained overlapping chunks we can perform a tcache poisoning attack by freeing the target chunk and overwriting the fd of the freed target chunk. Note that safe linking is enabled for this libc so we'll have to encrypt the address we want to allocate our chunk at using the address of the target chunk.

We also need to have another chunk in the tcache bins such that we can allocate from the the tcache twice.

Once we overwrite the free list pointers, we can allocate a chunk of the size of our target chunk twice to get it to allocate at the required address.

Now we can simply write the `environ` symbol pointer to the library array and read from the index we overwrote to get the stack leak.

### Ret2System

Now that we have our stack leak we can call system with `/bin/sh` as argument to create our ROP payload.

```py
rop = ROP(libc)
rop.raw(0xdeadbeef)
rop.raw(rfg(rop,['ret']))
rop.rdi = next(libc.search(b'/bin/sh\0'))
rop.raw(libc.sym['system'])
payload = rch(rop)
```

Now we need to write our payload to the return address of the review_chunk function to call system.

This will require another House of Einherjar into Tcache Poisoning to allocate a chunk near the return address.

![img-description](retaddr.png)

This is the return address of the `review_chunk` function which we need to overwrite.

### Final Exploit

You can find the challenge files and my exploit script [here](https://github.com/TheB4tMite/CTF-Writeups/tree/main/LACTF_25/library)