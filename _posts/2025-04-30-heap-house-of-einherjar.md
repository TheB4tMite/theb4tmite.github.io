---
layout: post
date: 2025-04-30 15:45:00 +0530
title: House of Einherjar
description: Review Notes on House of Einherjar
categories: Heap Attacks
tags: Notes Houses
media_subpath: /assets/media/heap-house-of-einherjar/
---

## Introduction
- This exploit technique allows us to use `malloc` to return a chunk at an almost arbitrary address within `av->system_mem` limits.
- We exploit the `malloc_consolidate` feature here.

## Code Review

```c
/* Consolidate backward.  */
  if (!prev_inuse(p))
    {
      INTERNAL_SIZE_T prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```
- When `malloc` is called it consolidates any continuous free chunk sequences within the free list.
- It checks whether the `PREV_INUSE` bit is set to ascertain whether the previous chunk is allocated or not.
- If the `PREV_INUSE` bit is not set, it reads the `PREV_SIZE` field to get the previous chunks size and adds it to the current chunk's size.
- The pointer to be returned is obtained by subtracting the previous chunk's size from the current chunk's address.
- The following check takes place - *Check if size of previous chunk and prevsize(p) match `(chunksize(p) != prevsize)` else `corrupted size vs. prev_size while consolidating`.
- The `unlink_chunk` function is called to unlink the chunk from the free list.
- This also entails the check for whether the `bk->fd` and `fd->bk` pointers point to the current chunk.

## Exploitation
![img-description](HoE_Concept.png)
- Using an off-by-one write we can set the `PREV_INUSE` bit of the next chunk to 0.
- We craft a fake chunk where we want the fake chunk pointer to be by setting the size of the chunk followed by the `fd` and `bk` pointing to the fake chunk.
- The `fd` and `bk` points to the fake chunk in order to bypass the `unlink_chunk` checks.
- We need to set the `PREV_SIZE` of the next chunk such that the address of the next chunk minus the prev size gives you the location of the fake chunk.
- Once these steps are done you can go ahead and free the victim chunk which will lead to consolidation and a pointer to your fake chunk being returned.
- One way to leverage this mechanism is to get overlapping chunks using the fake chunk over the chunk used to set the `PREV_INUSE` bit.
- This can be used to execute a [TCache Poisoning](/posts/heap-tcache-poisoning/) attack to get arbitrary write.

## Example Challenges
- [LACTF 2025 (library)](https://theb4tmite.github.io/posts/lactf-25-library/)
