---
layout: post
date: 2025-04-29 13:32:10 +0530
title: Largebin Attack
categories: Heap Bins
tags: Notes
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

```c
victim_index = largebin_index(size);
bck = bin_at(av, victim_index);
fwd = bck->fd;
```

- Checks if chunk belongs to large bin size.
- Sets backward pointer to arena address for the large bin index.
- Set forward pointer to forward of `bck`, i.e first chunk in the bin.

```c
/* Maintain large bins in sorted order */
if (fwd != bck) {
	/* Or with inuse bit to speed comparisons */
	size |= PREV_INUSE;

	/* If smaller than smallest, bypass loop below */
	assert(chunk_main_arena(bck->bk));
	if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk)) {
		fwd = bck;
		bck = bck->bk;

		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
```

- If the chunk is smaller than the smallest chunk in the bin this part is skipped.
- Else the following part is executed.

```c
	} else {
		assert(chunk_main_arena(fwd));
		while ((unsigned long)size < chunksize_nomask(fwd)) {
			fwd = fwd->fd_nextsize;
			assert(chunk_main_arena(fwd));
		}
```

- Traverse through the bin until the correct position is found.

```c
		if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd)) {
			/* Always insert in the second position. */
			fwd = fwd->fd;
		} else {
			victim->fd_nextsize = fwd;
			victim->bk_nextsize = fwd->bk_nextsize;
			if (__glibc_unlikely(fwd->bk_nextsize->fd_nextsize != fwd))
				malloc_printerr("malloc(): largebin double linked list corrupted (nextsize)");
			fwd->bk_nextsize = victim;
			victim->bk_nextsize->fd_nextsize = victim;
		}
		bck = fwd->bk;
		if (bck->fd != fwd)
			malloc_printerr("malloc(): largebin double linked list corrupted (bk)");
	}
} else {
	victim->fd_nextsize = victim->bk_nextsize = victim;
}
```
- *Check for whether forward chunk's `bk_nextsize` chunk's `fd_nextsize` pointer doesn't match with the forward pointer, else  `malloc(): largebin double linked list corrupted (nextsize)`.
- *Check for whether backward pointer's fd matches with the forward pointer else `malloc(): largebin double linked list corrupted (bk)`*.

## Exploitation
- Allocate a chunk that is of large bin size (p1) and another smaller chunk to prevent top chunk consolidation.
- Allocate another chunk that is of smaller size than the previous chunk but of the same large bin size, also add another chunk to prevent top chunk consolidation.
- Free the first chunk p1 and allocate another chunk larger than p1 such that p1 goes into the large bin.
- Free the second chunk p2 such that now we have one chunk in the large bin and one in the unsorted bin.
- Modify the bk_nextsize of chunk p1 to your target address - `0x20`.
- Allocate another chunk larger than p2 so that p2 goes into the large bin.
- This effectively bypasses the `bk_nextsize` check via taking the "smaller than smallest" loop path as the check doesn't take place here.
- This writes the address of the chunk p2 to the target address.

