---
layout: post
date: 2025-04-30 15:11:00 +0530
title: TCache Poisoning
description: Review Notes on TCache Poisoning
categories: Heap Attacks
tags: Notes Bins
media_subpath: /assets/media/heap-tcache-poisoning/
---

## Introduction
- Exploits the functionality of the `unlink_chunk` function.
- Allows writing an arbitrary 4/8-byte value to any write-able address

## Code Review
- Chunk forward pointer is initialised to the current chunk's fd pointer  `fd = p->fd`.
- Chunk backward pointer is initialised to the current chunk's bk pointer `bk = p->bk`.
- Forward chunk's backward pointer is updated to current chunk's backward pointer `fd->bk = bk`.
- Backward chunk's forward pointer is updated to current chunk's forward pointer `bk->fd = fd`.

## Exploitation
- Abuse an overflow in the heap to overwrite the next and prev pointers of the chunk being unlinked.
- `fd` and `bk` addresses will be overwritten with each other.
