---
layout: post
date: 2025-04-30 15:04:00 +0530
title: Safe-Linking
categories: Heap Mitigations
tags: Notes
math: true
description: Notes on Safe-Linking implementation.
media_subpath: /assets/media/heap-safe-linkin/
---

## Introduction
- Safe-Linking is a mitigation that was introduced in GLIBC 2.32.

## Code Review
- The pointers are mangled using the `PROTECT_PTR` and retrieved using the `REVEAL_PTR` macros.
- **PROTECT_PTR:**
```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
```
- **REVEAL_PTR:**
```c
#define REVEAL_PTR(ptr)  \
	PROTECT_PTR (&ptr, ptr)
```
- Essentially, the last 3 nibbles of the chunk's address are removed since these are the only parts that remain uncertain.
- The resulting address is then XOR'ed with the linked list pointer that we want at that position.
- The REVEAL_PTR macro just XOR's the mangled pointer with the chunk's address (the fact that the chunk changes doesn't matter as we only XOR with the unchanging significant bits) after removing the last 3 nibbles, this returns the original linked list pointer due to property of XOR having \$$ A \oplus B = C \$$  \$$ A \oplus C = B \$$

## Exploitation
- You can decrypt safe-linking if you pay attention to it's properties.
- Since the heap pointer used to XOR is right-shifted by 3 nibbles it means the the first 3 nibbles of the chunk address it has to XOR are never changed.
- This gives us the first 3 nibbles of the XOR key as a part of the encrypted pointer.
- If we manage to leak an encrypted pointer we can retrieve the actual pointer using the following method:
	- XOR the next 3 nibbles of the encrypted pointer using the first 3 nibbles of the pointer.
	- Repeat the step using the decrypted 3 nibbles of the pointer until the entire address is retrieved.
- The following function retrieves the decrypted pointer from the encrypted one.
```python
def dec_heap(heap_ptr):
	heap_ptr = hex(heap_ptr)
	j = 2
	for i in range(2,9,3):
		heap_ptr = hex(int(heap_ptr,16) ^ (int('0x'+heap_ptr[i:i+3],16)<<(12*j)))
		j -= 1
	return int(heap_ptr,16)
```

