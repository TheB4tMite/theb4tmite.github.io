---
layout: post
date: 2025-04-29 13:26:20 +0530
title: Fastbin Attack
categories: Heap Bins
tags: Notes
description: Review Notes on Fastbin Attack
media_subpath: /assets/media/heap-fastbin-attack/
---

## Introduction
- Exploits the ability to double free chunks if the pointer isn't properly destroyed.
- Allows arbitrary write.

## Code Review
- Freeing a chunk that is within the fastbin size range puts the chunk pointer of the freed chunk into the fastbin free list for that particular size.
- The `fd` and `bk` pointers are used to keep track of the forward and backward chunks in the free list.

## Exploitation
- Double Free a chunk to get two pointers to the same chunk in the fastbin free list.
- Overwrite the `fd` of the first entry of the chunk in the free list to the fake chunk pointer.
- This allows us to control the `fd` of the second chunk entry without a heap buffer overflow.
- Make sure the size header of the fake chunk aligns with the fastbin size index you're trying to allocate. { `malloc(): memory corruption (fast)` }
- Allocating the specific fastbin size should allocate the fake chunk.

## Example Challenges
- [Insomnihack Teaser 2022 (OneTestament)](https://ctftime.org/writeup/32227)

## Notes
- Messing with the `mmap` bit can potentially bypass some checks.
- Set `mmap` bit to bypass `calloc` nulling out the address space it allocates.
