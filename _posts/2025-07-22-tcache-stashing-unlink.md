---
layout: post
date: 2025-07-22 11:00 +0530
title: TCache Stashing Unlink
description: Review Notes on TCache Stashing Unlink
categories: Heap Attacks
tags: Notes Bins Attacks
media_subpath: /assets/media/heap-tcache-stashing-unlink/
---

## Introduction
- Exploits a UAF or an overflow into the victim's `bk` pointer.
- Allows arbitrary fake chunk allocation.

## Code Review

### Smallbins
- The smallbin is a circular doubly-linked list.
- These chunks can be coalesced to form larger chunks.
- If a request satisfies smallbin size range then the smallbins are checked.
- For large requests, largebins are only checked once unsorted chunks are sorted.
- The bin index for the size is obtained and the `bin` is intialised to the linked-list at that index.
```c
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);
```
- A check takes place for whether the last chunk in the bin is the same as the first chunk in the bin.
- If not, `bck` is initialised to the chunk before the last chunk in the bin.
```c
  if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
```
- A check for whether `bck`'s forward pointer correctly points to the `victim` chunk takes place to mitigate any memory corruption.
- If not, the `victim` chunk is unlinked from the list after the `inuse` bit is set.
- `bin->bk` is set to the 2nd last chunk in the bin.
- `bck->fd` is set to the beginning of the linked-list completing the circular link.
```c
      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;
```
- A check takes place for whether the `malloc_state` struct pointer is equal to the `main_arena`. If not, then the `NMA` bit is set .
- `check_malloced_chunk` is a function that checks for chunk sanity in debug builds.
```c
          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
```
### TCache
- If chunks of the same size as the requested size range are found, they are exhaustively stashed in the tcache until it's full for quick retrieval.
- `tc_idx` is set to the tcache index for the chunk size that has been requested.
```c
	  size_t tc_idx = csize2tidx (nb);
```
- A check for whether the tcache has been initialised and if `tc_idx` is less that the no. of total tcache bins.
- `tc_victim` is initialised, this is the chunk that will be taken out of the tcache.
- A loop is initialised which continues as long as the following conditions are satisfied:
	- The bin count for the `tc_idx` is less than the max `tcache_count`.
	- The current `tc_victim` is not the last chunk in the small `bin`.
```c
	  if (tcache != NULL && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
```
- Another check for whether the `tc_victim` is null.
- If not, `bck` is set to the `tc_victim`'s previous chunk.
- `prev_inuse` is set for the `tc_victim`.
- `nma` bit is set if required.
- `tc_victim` is unlinked from the smallbin.
- `tc_victim` is added to the tcache bin for `tc_idx` and the `tcache->counts[tc_idx]`
 is incremented.
 ```c

		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
```
- If the request was not satisfied by the smallbins then the largebin index for the size is obtained and the fastbins are consolidated before proceeding.
```c
{
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }
```
## Exploitation
- Fill up the tcache bins for a certain size (`0x90` recommended) by allocating upto 9 chunks and freeing 7 of them such that the 2nd and 4th chunk are still free.
- Free the 2nd and 4th chunk to put them into the unsorted bin, allocate a chunk larger than both of them to sort them into the smallbin.
- Malloc 2 chunks to remove 2 spaces from the tcachebin.
- Overwrite the `victim-bk` using the vulnerability to your target address/chain.
- Allocate a chunk from of the smallbin size and your fake chunk should get stashed into tcache.
