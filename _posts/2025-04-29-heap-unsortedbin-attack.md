---
layout: post
date: 2025-04-29 13:35:30 +0530
title: Unsortedbin Attack
categories: Heap Attacks
tags: Notes Bins
description: Review Notes on Unsortedbin Attack
media_subpath: /assets/media/heap-unsortedbin-attack/
---

## Introduction
- Exploits the implementation of removing an unsorted bin chunk from the list by overwriting a free unsorted bin chunk's `bk` pointer.
- Allows writing an unsorted bin address to an arbitrary location.
- This technique has been patched since GLIBC 2.29 onwards.

## Code Review
- When a unsorted chunk is removed from the free list the following code executes.
```c
​/* remove from unsorted list */                                                      
	unsorted_chunks (av)->bk = bck;
	bck->fd = unsorted_chunks (av);
```
- `bck->fd` is set to unsorted_chunks (av), which means if we can control the `bk` value, we can set an arbitrary location to `unsorted_chunks (av)`.

## Exploitation
- Requires using a UAF or any other primitive that allows you to write into a freed unsorted bin chunk.
- Overwrite the `bk` pointer of the unsorted chunk with the address you want to overwrite `addr - 0x10`.
- One possible target is overwriting the `global_max_fast` variable which keeps track of the maximum permissible size of the fastbin chunks.
- Overwriting `global_max_fast` allows us to use the fastbin attack with any chunk-size.

## Example Challenges
- [0CTF (zer0storage)](https://guyinatuxedo.github.io/31-unsortedbin_attack/0ctf16_zerostorage/index.html)

## Notes
- Note that the unsorted bin list might be corrupted after the write.
