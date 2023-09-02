// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <objtool/bit_operations.h>
#include <objtool/warn.h>

u64 replicate(u64 x, int size, int n)
{
	u64 ret = 0;

	while (n >= 0) {
		ret = (ret | x) << size;
		n--;
	}
	return ret | x;
}

u64 ror(u64 x, int size, int shift)
{
	int m = shift % size;

	if (shift == 0)
		return x;
	return ZERO_EXTEND((x >> m) | (x << (size - m)), size);
}

int highest_set_bit(u32 x)
{
	int i;

	for (i = 31; i >= 0; i--, x <<= 1)
		if (x & 0x80000000)
			return i;
	return 0;
}

/* imms and immr are both 6 bit long */
__uint128_t decode_bit_masks(unsigned char N, unsigned char imms,
			     unsigned char immr, bool immediate)
{
	u64 tmask, wmask;
	u32 diff, S, R, esize, welem, telem;
	unsigned char levels = 0, len = 0;

	len = highest_set_bit((N << 6) | ((~imms) & ONES(6)));
	levels = ZERO_EXTEND(ONES(len), 6);

	if (immediate && ((imms & levels) == levels)) {
		WARN("unknown instruction");
		return -1;
	}

	S = imms & levels;
	R = immr & levels;
	diff = ZERO_EXTEND(S - R, 6);

	esize = 1 << len;
	diff = diff & ONES(len);

	welem = ZERO_EXTEND(ONES(S + 1), esize);
	telem = ZERO_EXTEND(ONES(diff + 1), esize);

	wmask = replicate(ror(welem, esize, R), esize, 64 / esize);
	tmask = replicate(telem, esize, 64 / esize);

	return ((__uint128_t)wmask << 64) | tmask;
}
