---
layout: post
date: 2025-04-29 13:32:10 +0530
title: Largebin Attack
categories: Heap Attacks
tags: Notes Bins
description: Review Notes on Largebin Attack
media_subpath: /assets/media/heap-largebin-attack/
---

## Introduction
- Requires some method to modify chunk `bk_nextsize`.
- Allows writing the large bin head chunk address to an arbitrary address.

## Code Review
- The large bins range from size `0x400` onwards.
- The large bin is maintained in sorted order.
- Has 2 separate pointers for forward and backward `fd_nextsize` and `bk_nextsize`.
- Large bin chunks have 2 pointers `fd_nextsize` and `bk_nextsize` which points to the next and previous chunks respectively.
- Large bin chunks can split into smaller chunks as required.
- `victim_index` is initialised to the largebin index for the requested size.
- Sets `bck` pointer to linked-list at the `victim_index`.
- Set `fwd` to forward of `bck`, i.e first chunk in the bin
```c
victim_index = largebin_index(size);
bck = bin_at(av, victim_index);
fwd = bck->fd;
```
- Check for whether `fwd` is equal to `bck`, i.e, there are no more chunks in the list except the sentinel chunk.
- If yes, the chunk is inserted directly into the largebin.
- `size` is or'd with `PREV_INUSE` to speed up comparisons by avoiding the bit-masking step.
- `bck->bk` points to the last chunk in the bin, the assertion checks whether it belongs to the main arena to catch race conditions where a chunk from a different thread arena gets linked into the bin.
```c
/* Maintain large bins in sorted order */
if (fwd != bck) {
	/* Or with inuse bit to speed comparisons */
	size |= PREV_INUSE;
	
	/* If smaller than smallest, bypass loop below */
	assert(chunk_main_arena(bck->bk));
```
- If the `size` of the chunk is less than that of the smallest chunk in the bin (since the largebins are sorted in descending order) the following part is executed.
- `fwd` is set to the previous chunk, i.e, the bin header.
- `bck` is set to the smallest chunk in the bin.
- `victim->fd_nextsize` is set to `fwd->fd`, i.e, the first chunk in the bin.
- `victim->bk_nextsize` is set to `fwd->fd->bk_nextsize`, i.e, the smallest chunk in the bin.
- `fwd->fd->bk_nextsize` is set to `victim->bk_nextsize->fd_nextsize` which is set to `victim`, i.e, the `victim` chunk is linked to the smallest bin chunk's `fd_nextsize` and the first bin chunk's `bk_nextsize`.
```c
	if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk)) {
		fwd = bck;
		bck = bck->bk;

		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
```

- If the chunk is not the smallest chunk to be added to the list then the following is executed.
- Loops through the nextsize list to find the current position of the chunk in the list while checking whether each chunk is part of the main arena.

```c
	} else {
		assert(chunk_main_arena(fwd));
		while ((unsigned long)size < chunksize_nomask(fwd)) {
			fwd = fwd->fd_nextsize;
			assert(chunk_main_arena(fwd));
		}
```

- If the an existing chunk is found in the bin with the same size, then the chunk will be inserted in the second position of the sub-list of that size.
```c
		if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd)) {
			/* Always insert in the second position. */
			fwd = fwd->fd;
```
- Otherwise the chunk is inserted normally.
- `victim->fd_nextsize` is set to the next size chunk at that position.
- `victim->bk_nextsize` is set to the previous size chunk at that position.
- A check for whether the `bk_nextsize` and `fd_nextsize` of the `fwd` chunk is corrupted takes place.
- If the check passes, the `victim` chunk is linked into the list.
- `fwd->bk_nextsize` is set to the `victim`.
- `victim->bk_nextsize->fd_nextsize` is set to `victim`, linking the previous and forward chunks. 

```c
		} else {
			victim->fd_nextsize = fwd;
			victim->bk_nextsize = fwd->bk_nextsize;
			if (__glibc_unlikely(fwd->bk_nextsize->fd_nextsize != fwd))
				malloc_printerr("malloc(): largebin double linked list corrupted (nextsize)");
			fwd->bk_nextsize = victim;
			victim->bk_nextsize->fd_nextsize = victim;
		}
```
- If the chunk is to be directly added to the list as the bin is empty, then the following part executes.
- `bck` is initialised to `fwd->bk`, i.e, the chunk before the end chunk.
- A check for whether the first chunk in the list has been manipulated is done.
```c
		bck = fwd->bk;
		if (bck->fd != fwd)
			malloc_printerr("malloc(): largebin double linked list corrupted (bk)");
	}
```
- If the bin is empty, then the `victim` is added to the list by linking it to itself in the nextsize list.
 ```c
} else {
	victim->fd_nextsize = victim->bk_nextsize = victim;
}
```
- Finally, `mark_bin` marks the bin at that index as non-empty, this is done so that empty bins can be quickly identified using a binmap implementation.
- `victim` is linked into the actual largebin list. 
```c
	  mark_bin (av, victim_index);
	  victim->bk = bck;
	  victim->fd = fwd;
	  fwd->bk = victim;
	  bck->fd = victim;
```

## Exploitation
- Allocate a chunk that is of large bin size (p1) and another smaller chunk to prevent top chunk consolidation.
- Allocate another chunk that is of smaller size than the previous chunk but of the same large bin size, also add another chunk to prevent top chunk consolidation.
- Free the first chunk p1 and allocate another chunk larger than p1 such that p1 goes into the large bin.
- Free the second chunk p2 such that now we have one chunk in the large bin and one in the unsorted bin.
- Modify the bk_nextsize of chunk p1 to your target address - `0x20`.
- Allocate another chunk larger than p2 so that p2 goes into the large bin.
- This effectively bypasses the `bk_nextsize` check via taking the "smaller than smallest" loop path as the check doesn't take place here.
- This writes the address of the chunk p2 to the target address.

