/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file contains an OpenCL kernel for performing certain parts of
 * the bitcoin address calculation process.
 *
 * Kernel: ec_add_grid
 *
 * Inputs:
 * - Row: Array of (sequential) EC points
 * - Column: Array of column increment EC points (= rowsize * Pgenerator)
 *
 * Steps:
 * - Compute P = Row[x] + Column[y]
 *   P is computed as numerator/denominator components Pxj, Pyj, Pz
 *   Final values are: Px = Pxj / (Pz^2), Py = Pyj / (Pz^3)
 *
 *   The modular inverse of Pz is required to compute Px and Py, and
 *   can be computed more efficiently in large batches.  This is done in
 *   the next kernel heap_invert.
 *
 * - Store Pxj, Pyj to intermediate point buffer
 * - Store Pz to z_heap
 *
 * Outputs:
 * - Intermediate point buffer
 * - Denominator buffer (z_heap)
 *
 * -------------------------------
 * Kernel: heap_invert
 *
 * Inputs:
 * - Denominator buffer (z_heap)
 * - N = Batch size (power of 2)
 *
 * Steps:
 * - Compute the product tree for N values in the denominator buffer
 * - Compute the modular inverse of the root of the product tree
 * - Multiply down the tree to compute the modular inverse of each leaf
 *
 * Outputs:
 * - Modular inverse denominator buffer (z_heap)
 *
 * -------------------------------
 * Kernel: hash_ec_point_get
 *
 * Inputs:
 * - Intermediate point buffer
 * - Modular inverse denominator buffer (z_heap)
 *
 * Steps:
 * - Compute Px = Pxj * (1/Pz)^2
 * - Compute Py = Pyj * (1/Pz)^3
 * - Compute H = RIPEMD160(SHA256(0x04 | Px | Py))
 *
 * Output:
 * - Array of 20-byte address hash values
 *
 * -------------------------------
 * Kernel: hash_ec_point_search_prefix
 *
 * Like hash_ec_point_get, but instead of storing the complete hash
 * value to an output buffer, it searches a sorted list of ranges,
 * and if a match is found, writes a flag to an output buffer.
 */


/* Byte-swapping and endianness */
#define bswap32(v)					\
	(((v) >> 24) | (((v) >> 8) & 0xff00) |		\
	 (((v) << 8) & 0xff0000) | ((v) << 24))

#if __ENDIAN_LITTLE__ != 1
#define load_le32(v) bswap32(v)
#define load_be32(v) (v)
#else
#define load_le32(v) (v)
#define load_be32(v) bswap32(v)
#endif

/*
 * Loop unrolling macros
 *
 * In most cases, preprocessor unrolling works best.
 * The exception is NVIDIA's compiler, which seems to take unreasonably
 * long to compile a loop with a larger iteration count, or a loop with
 * a body of >50 PTX instructions, with preprocessor unrolling.
 * However, it does not seem to take as long with pragma unroll, and
 * produces good output.
 */

/* Explicit loop unrolling */
#define unroll_5(a) do { a(0) a(1) a(2) a(3) a(4) } while (0)
#define unroll_8(a) do { a(0) a(1) a(2) a(3) a(4) a(5) a(6) a(7) } while (0)
#define unroll_1_7(a) do { a(1) a(2) a(3) a(4) a(5) a(6) a(7) } while (0)
#define unroll_7(a) do { a(0) a(1) a(2) a(3) a(4) a(5) a(6) } while (0)
#define unroll_7_0(a) do { a(7) a(6) a(5) a(4) a(3) a(2) a(1) a(0) } while (0)
#define unroll_7_1(a) do { a(7) a(6) a(5) a(4) a(3) a(2) a(1) } while (0)
#define unroll_16(a) do {				\
	a(0) a(1) a(2) a(3) a(4) a(5) a(6) a(7)		\
	a(8) a(9) a(10) a(11) a(12) a(13) a(14) a(15)	\
	} while (0)
#define unroll_64(a) do {				\
	a(0) a(1) a(2) a(3) a(4) a(5) a(6) a(7)		\
	a(8) a(9) a(10) a(11) a(12) a(13) a(14) a(15)	\
	a(16) a(17) a(18) a(19) a(20) a(21) a(22) a(23) \
	a(24) a(25) a(26) a(27) a(28) a(29) a(30) a(31)	\
	a(32) a(33) a(34) a(35) a(36) a(37) a(38) a(39) \
	a(40) a(41) a(42) a(43) a(44) a(45) a(46) a(47) \
	a(48) a(49) a(50) a(51) a(52) a(53) a(54) a(55) \
	a(56) a(57) a(58) a(59) a(60) a(61) a(62) a(63) \
	} while (0)

/* Conditional loop unrolling */
#if defined(DEEP_PREPROC_UNROLL)
#define iter_5(a) unroll_5(a)
#define iter_8(a) unroll_8(a)
#define iter_16(a) unroll_16(a)
#define iter_64(a) unroll_64(a)
#else
#define iter_5(a) do {int _i; for (_i = 0; _i < 5; _i++) { a(_i) }} while (0)
#define iter_8(a) do {int _i; for (_i = 0; _i < 8; _i++) { a(_i) }} while (0)
#define iter_16(a) do {int _i; for (_i = 0; _i < 16; _i++) { a(_i) }} while (0)
#define iter_64(a) do {int _i; for (_i = 0; _i < 64; _i++) { a(_i) }} while (0)
#endif

/*
 * BIGNUM mini-library
 * This module deals with fixed-size 256-bit bignums.
 * Where modular arithmetic is performed, the SECP256k1 prime
 * modulus (below) is assumed.
 *
 * Methods include:
 * - bn_is_zero/bn_is_one/bn_is_odd/bn_is_even/bn_is_bit_set
 * - bn_rshift[1]/bn_lshift[1]
 * - bn_neg
 * - bn_uadd/bn_uadd_p
 * - bn_usub/bn_usub_p
 */

typedef uint bn_word;
#define BN_NBITS 256
#define BN_WSHIFT 5
#define BN_WBITS (1 << BN_WSHIFT)
#define BN_NWORDS ((BN_NBITS/8) / sizeof(bn_word))
#define BN_WORDMAX 0xffffffff

#define MODULUS_BYTES \
	0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, \
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff

typedef struct {
	bn_word d[BN_NWORDS];
} bignum;

__constant bn_word modulus[] = { MODULUS_BYTES };
__constant bignum bn_zero;

__constant bn_word mont_rr[BN_NWORDS] = { 0xe90a1, 0x7a2, 0x1, 0, };
__constant bn_word mont_n0[2] = { 0xd2253531, 0xd838091d };


#define bn_is_odd(bn)		(bn.d[0] & 1)
#define bn_is_even(bn) 		(!bn_is_odd(bn))
#define bn_is_zero(bn) 		(!bn.d[0] && !bn.d[1] && !bn.d[2] && \
				 !bn.d[3] && !bn.d[4] && !bn.d[5] && \
				 !bn.d[6] && !bn.d[7])
#define bn_is_one(bn) 		((bn.d[0] == 1) && !bn.d[1] && !bn.d[2] && \
				 !bn.d[3] && !bn.d[4] && !bn.d[5] && \
				 !bn.d[6] && !bn.d[7])
#define bn_is_bit_set(bn, n) \
	((((bn_word*)&bn)[n >> BN_WSHIFT]) & (1 << (n & (BN_WBITS-1))))

#define bn_unroll(e) unroll_8(e)
#define bn_unroll_sf(e)	unroll_1_7(e)
#define bn_unroll_sl(e)	unroll_7(e)
#define bn_unroll_reverse(e) unroll_7_0(e)
#define bn_unroll_reverse_sl(e) unroll_7_1(e)

#define bn_unroll_arg(e, arg)				\
	e(arg, 0) e(arg, 1) e(arg, 2) e(arg, 3)	\
	e(arg, 4) e(arg, 5) e(arg, 6) e(arg, 7)
#define bn_unroll_arg_sf(e, arg)			\
	e(arg, 1) e(arg, 2) e(arg, 3)		\
	e(arg, 4) e(arg, 5) e(arg, 6) e(arg, 7)

#define bn_iter(e) iter_8(e)


/*
 * Bitwise shift
 */

void
bn_lshift1(bignum *bn)
{
#define bn_lshift1_inner1(i)						\
		bn->d[i] = (bn->d[i] << 1) | (bn->d[i-1] >> 31);
	bn_unroll_reverse_sl(bn_lshift1_inner1);
	bn->d[0] <<= 1;
}

void
bn_rshift(bignum *bn, int shift)
{
	int wd, iws, iwr;
	bn_word ihw, ilw;
	iws = (shift & (BN_WBITS-1));
	iwr = BN_WBITS - iws;
	wd = (shift >> BN_WSHIFT);
	ihw = (wd < BN_WBITS) ? bn->d[wd] : 0;

#define bn_rshift_inner1(i)				\
		wd++;					\
		ilw = ihw;				\
		ihw = (wd < BN_WBITS) ? bn->d[wd] : 0;	\
		bn->d[i] = (ilw >> iws) | (ihw << iwr);
	bn_unroll_sl(bn_rshift_inner1);
	bn->d[BN_NWORDS-1] = (ihw >> iws);
}

void
bn_rshift1(bignum *bn)
{
#define bn_rshift1_inner1(i)						\
		bn->d[i] = (bn->d[i+1] << 31) | (bn->d[i] >> 1);
	bn_unroll_sl(bn_rshift1_inner1);
	bn->d[BN_NWORDS-1] >>= 1;
}

void
bn_rshift1_2(bignum *bna, bignum *bnb)
{
#define bn_rshift1_2_inner1(i)						\
		bna->d[i] = (bna->d[i+1] << 31) | (bna->d[i] >> 1);	\
		bnb->d[i] = (bnb->d[i+1] << 31) | (bnb->d[i] >> 1);
	bn_unroll_sl(bn_rshift1_2_inner1);
	bna->d[BN_NWORDS-1] >>= 1;
	bnb->d[BN_NWORDS-1] >>= 1;
}


/*
 * Unsigned comparison
 */

int
bn_ucmp_ge(bignum *a, bignum *b)
{
	int l = 0, g = 0;

#define bn_ucmp_ge_inner1(i)				\
		if (a->d[i] < b->d[i]) l |= (1 << i);	\
		if (a->d[i] > b->d[i]) g |= (1 << i);
	bn_unroll_reverse(bn_ucmp_ge_inner1);
	return (l > g) ? 0 : 1;
}

int
bn_ucmp_ge_c(bignum *a, __constant bn_word *b)
{
	int l = 0, g = 0;

#define bn_ucmp_ge_c_inner1(i)				\
		if (a->d[i] < b[i]) l |= (1 << i);	\
		if (a->d[i] > b[i]) g |= (1 << i);
	bn_unroll_reverse(bn_ucmp_ge_c_inner1);
	return (l > g) ? 0 : 1;
}

/*
 * Negate
 */

void
bn_neg(bignum *n)
{
	int c = 1;

#define bn_neg_inner1(i)				\
		c = (n->d[i] = (~n->d[i]) + c) ? 0 : c;
	bn_unroll(bn_neg_inner1);
}

/*
 * Add/subtract
 */

#define bn_add_word(r, a, b, t, c) do {		\
		t = a + b;			\
		c = (t < a) ? 1 : 0;		\
		r = t;				\
	} while (0)

#define bn_addc_word(r, a, b, t, c) do {			\
		t = a + b + c;					\
		c = (t < a) ? 1 : ((c & (t == a)) ? 1 : 0);	\
		r = t;						\
	} while (0)

bn_word
bn_uadd_words_seq(bn_word *r, bn_word *a, bn_word *b)
{
	bn_word t, c = 0;

#define bn_uadd_words_seq_inner1(i)			\
		bn_addc_word(r[i], a[i], b[i], t, c);
	bn_add_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_uadd_words_seq_inner1);
	return c;
}

bn_word
bn_uadd_words_c_seq(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bn_word t, c = 0;

	bn_add_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_uadd_words_seq_inner1);
	return c;
}

#define bn_sub_word(r, a, b, t, c) do {		\
		t = a - b;			\
		c = (a < b) ? 1 : 0;		\
		r = t;				\
	} while (0)

#define bn_subb_word(r, a, b, t, c) do {	\
		t = a - (b + c);		\
		c = (!(a) && c) ? 1 : 0;	\
		c |= (a < b) ? 1 : 0;		\
		r = t;				\
	} while (0)

bn_word
bn_usub_words_seq(bn_word *r, bn_word *a, bn_word *b)
{
	bn_word t, c = 0;

#define bn_usub_words_seq_inner1(i)			\
		bn_subb_word(r[i], a[i], b[i], t, c);

	bn_sub_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_usub_words_seq_inner1);
	return c;
}

bn_word
bn_usub_words_c_seq(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bn_word t, c = 0;

	bn_sub_word(r[0], a[0], b[0], t, c);
	bn_unroll_sf(bn_usub_words_seq_inner1);
	return c;
}

/*
 * Add/subtract better suited for AMD's VLIW architecture
 */
bn_word
bn_uadd_words_vliw(bn_word *r, bn_word *a, bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

#define bn_uadd_words_vliw_inner1(i)		\
		x.d[i] = a[i] + b[i];

#define bn_uadd_words_vliw_inner2(i)			\
		c |= (a[i] > x.d[i]) ? (1 << i) : 0;	\
		cp |= (!~x.d[i]) ? (1 << i) : 0;

#define bn_uadd_words_vliw_inner3(i)		\
		r[i] = x.d[i] + ((c >> i) & 1);

	bn_unroll(bn_uadd_words_vliw_inner1);
	bn_unroll(bn_uadd_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_uadd_words_vliw_inner3);
	return c >> BN_NWORDS;
}

bn_word
bn_uadd_words_c_vliw(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

	bn_unroll(bn_uadd_words_vliw_inner1);
	bn_unroll(bn_uadd_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_uadd_words_vliw_inner3);
	return c >> BN_NWORDS;
}

bn_word
bn_usub_words_vliw(bn_word *r, bn_word *a, bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

#define bn_usub_words_vliw_inner1(i)		\
		x.d[i] = a[i] - b[i];

#define bn_usub_words_vliw_inner2(i)			\
		c |= (a[i] < b[i]) ? (1 << i) : 0;	\
		cp |= (!x.d[i]) ? (1 << i) : 0;

#define bn_usub_words_vliw_inner3(i)		\
		r[i] = x.d[i] - ((c >> i) & 1);

	bn_unroll(bn_usub_words_vliw_inner1);
	bn_unroll(bn_usub_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_usub_words_vliw_inner3);
	return c >> BN_NWORDS;
}

bn_word
bn_usub_words_c_vliw(bn_word *r, bn_word *a, __constant bn_word *b)
{
	bignum x;
	bn_word c = 0, cp = 0;

	bn_unroll(bn_usub_words_vliw_inner1);
	bn_unroll(bn_usub_words_vliw_inner2);
	c = ((cp + (c << 1)) ^ cp);
	r[0] = x.d[0];
	bn_unroll_sf(bn_usub_words_vliw_inner3);
	return c >> BN_NWORDS;
}


#if defined(DEEP_VLIW)
#define bn_uadd_words bn_uadd_words_vliw
#define bn_uadd_words_c bn_uadd_words_c_vliw
#define bn_usub_words bn_usub_words_vliw
#define bn_usub_words_c bn_usub_words_c_vliw
#else
#define bn_uadd_words bn_uadd_words_seq
#define bn_uadd_words_c bn_uadd_words_c_seq
#define bn_usub_words bn_usub_words_seq
#define bn_usub_words_c bn_usub_words_c_seq
#endif

#define bn_uadd(r, a, b) bn_uadd_words((r)->d, (a)->d, (b)->d)
#define bn_uadd_c(r, a, b) bn_uadd_words_c((r)->d, (a)->d, b)
#define bn_usub(r, a, b) bn_usub_words((r)->d, (a)->d, (b)->d)
#define bn_usub_c(r, a, b) bn_usub_words_c((r)->d, (a)->d, b)

/*
 * Modular add/sub
 */

void
bn_mod_add(bignum *r, bignum *a, bignum *b)
{
	if (bn_uadd(r, a, b) ||
	    (bn_ucmp_ge_c(r, modulus)))
		bn_usub_c(r, r, modulus);
}

void
bn_mod_sub(bignum *r, bignum *a, bignum *b)
{
	if (bn_usub(r, a, b))
		bn_uadd_c(r, r, modulus);
}

void
bn_mod_lshift1(bignum *bn)
{
	bn_word c = (bn->d[BN_NWORDS-1] & 0x80000000);
	bn_lshift1(bn);
	if (c || (bn_ucmp_ge_c(bn, modulus)))
		bn_usub_c(bn, bn, modulus);
}

/*
 * Montgomery multiplication
 *
 * This includes normal multiplication of two "Montgomeryized"
 * bignums, and bn_from_mont for de-Montgomeryizing a bignum.
 */

#define bn_mul_word(r, a, w, c, p, s) do { \
		r = (a * w) + c;	   \
		p = mul_hi(a, w);	   \
		c = (r < c) ? p + 1 : p;   \
	} while (0)

#define bn_mul_add_word(r, a, w, c, p, s) do {	\
		s = r + c;			\
		p = mul_hi(a, w);		\
		r = (a * w) + s;		\
		c = (s < c) ? p + 1 : p;	\
		if (r < s) c++;			\
	} while (0)
void
bn_mul_mont(bignum *r, bignum *a, bignum *b)
{
	bignum t;
	bn_word tea, teb, c, p, s, m;

#if !defined(VERY_EXPENSIVE_BRANCHES)
	int q;
#endif

	c = 0;
#define bn_mul_mont_inner1(j)					\
		bn_mul_word(t.d[j], a->d[j], b->d[0], c, p, s);
	bn_unroll(bn_mul_mont_inner1);
	tea = c;
	teb = 0;

	c = 0;
	m = t.d[0] * mont_n0[0];
	bn_mul_add_word(t.d[0], modulus[0], m, c, p, s);
#define bn_mul_mont_inner2(j)						\
		bn_mul_add_word(t.d[j], modulus[j], m, c, p, s);	\
		t.d[j-1] = t.d[j];
	bn_unroll_sf(bn_mul_mont_inner2);
	t.d[BN_NWORDS-1] = tea + c;
	tea = teb + ((t.d[BN_NWORDS-1] < c) ? 1 : 0);

#define bn_mul_mont_inner3_1(i, j)					\
		bn_mul_add_word(t.d[j], a->d[j], b->d[i], c, p, s);
#define bn_mul_mont_inner3_2(i, j)					\
		bn_mul_add_word(t.d[j], modulus[j], m, c, p, s);	\
		t.d[j-1] = t.d[j];
#define bn_mul_mont_inner3(i)				 \
	c = 0;						 \
	bn_unroll_arg(bn_mul_mont_inner3_1, i);		 \
	tea += c;					 \
	teb = ((tea < c) ? 1 : 0);			 \
	c = 0;						 \
	m = t.d[0] * mont_n0[0];			 \
	bn_mul_add_word(t.d[0], modulus[0], m, c, p, s); \
	bn_unroll_arg_sf(bn_mul_mont_inner3_2, i);	 \
	t.d[BN_NWORDS-1] = tea + c;			 \
	tea = teb + ((t.d[BN_NWORDS-1] < c) ? 1 : 0);

	/*
	 * The outer loop here is quite long, and we won't unroll it
	 * unless VERY_EXPENSIVE_BRANCHES is set.
	 */
#if defined(VERY_EXPENSIVE_BRANCHES)
	bn_unroll_sf(bn_mul_mont_inner3);
	c = tea | !bn_usub_c(r, &t, modulus);
	if (!c)
		*r = t;

#else
	for (q = 1; q < BN_NWORDS; q++) {
		bn_mul_mont_inner3(q);
	}
	c = tea || (t.d[BN_NWORDS-1] >= modulus[BN_NWORDS-1]);
	if (c) {
		c = tea | !bn_usub_c(r, &t, modulus);
		if (c)
			return;
	}
	*r = t;
#endif
}

void
bn_from_mont(bignum *rb, bignum *b)
{
#define WORKSIZE ((2*BN_NWORDS) + 1)
	bn_word r[WORKSIZE];
	bn_word m, c, p, s;
#if defined(PRAGMA_UNROLL)
	int i;
#endif

	/* Copy the input to the working area */
	/* Zero the upper words */
#define bn_from_mont_inner1(i)			\
	r[i] = b->d[i];
#define bn_from_mont_inner2(i)			\
	r[BN_NWORDS+i] = 0;

	bn_unroll(bn_from_mont_inner1);
	bn_unroll(bn_from_mont_inner2);
	r[WORKSIZE-1] = 0;

	/* Multiply (long) by modulus */
#define bn_from_mont_inner3_1(i, j) \
	bn_mul_add_word(r[i+j], modulus[j], m, c, p, s);

#if !defined(VERY_EXPENSIVE_BRANCHES)
#define bn_from_mont_inner3_2(i)		\
	if (r[BN_NWORDS + i] < c)		\
		r[BN_NWORDS + i + 1] += 1;
#else
#define bn_from_mont_inner3_2(i)				\
	r[BN_NWORDS + i + 1] += (r[BN_NWORDS + i] < c) ? 1 : 0;
#endif

#define bn_from_mont_inner3(i)			 \
	m = r[i] * mont_n0[0];			 \
	c = 0;					 \
	bn_unroll_arg(bn_from_mont_inner3_1, i); \
	r[BN_NWORDS + i] += c;			 \
	bn_from_mont_inner3_2(i)

	/*
	 * The outer loop here is not very long, so we will unroll
	 * it by default.  However, it's just complicated enough to
	 * cause NVIDIA's compiler to take unreasonably long to compile
	 * it, unless we use pragma unroll.
	 */
#if !defined(PRAGMA_UNROLL)
	bn_iter(bn_from_mont_inner3);
#else
#pragma unroll 8
	for (i = 0; i < BN_NWORDS; i++) { bn_from_mont_inner3(i) }
#endif

	/*
	 * Make sure the result is less than the modulus.
	 * Subtracting is not much more expensive than compare, so
	 * subtract always and assign based on the carry out value.
	 */
	c = bn_usub_words_c(rb->d, &r[BN_NWORDS], modulus);
	if (c) {
#define bn_from_mont_inner4(i)				\
			rb->d[i] = r[BN_NWORDS + i];
		bn_unroll(bn_from_mont_inner4);
	}
}

/*
 * Modular inversion
 */

void
bn_mod_inverse(bignum *r, bignum *n)
{
	bignum a, b, x, y;
	int shift;
	bn_word xc, yc;
	for (shift = 0; shift < BN_NWORDS; shift++) {
		a.d[shift] = modulus[shift];
		x.d[shift] = 0;
		y.d[shift] = 0;
	}
	b = *n;
	x.d[0] = 1;
	xc = 0;
	yc = 0;
	while (!bn_is_zero(b)) {
		shift = 0;
		while (!bn_is_odd(b)) {
			if (bn_is_odd(x))
				xc += bn_uadd_c(&x, &x, modulus);
			bn_rshift1_2(&x, &b);
			x.d[7] |= (xc << 31);
			xc >>= 1;
		}

		while (!bn_is_odd(a)) {
			if (bn_is_odd(y))
				yc += bn_uadd_c(&y, &y, modulus);
			bn_rshift1_2(&y, &a);
			y.d[7] |= (yc << 31);
			yc >>= 1;
		}

		if (bn_ucmp_ge(&b, &a)) {
			xc += yc + bn_uadd(&x, &x, &y);
			bn_usub(&b, &b, &a);
		} else {
			yc += xc + bn_uadd(&y, &y, &x);
			bn_usub(&a, &a, &b);
		}
	}

	if (!bn_is_one(a)) {
		/* no modular inverse */
		*r = bn_zero;
	} else {
		/* Compute y % m as cheaply as possible */
		while (yc < 0x80000000)
			yc -= bn_usub_c(&y, &y, modulus);
		bn_neg(&y);
		*r = y;
	}
}

/*
 * HASH FUNCTIONS
 *
 * BYTE ORDER NOTE: None of the hash functions below deal with byte
 * order.  The caller is expected to be aware of this when it stuffs
 * data into in the native integer.
 *
 * NOTE #2: Endianness of the OpenCL device makes no difference here.
 */

#define hash256_unroll(a) unroll_8(a)
#define hash160_unroll(a) unroll_5(a)
#define hash256_iter(a) iter_8(a)
#define hash160_iter(a) iter_5(a)


/*
 * SHA-2 256
 *
 * CAUTION: Input buffer will be overwritten/mangled.
 * Data expected in big-endian format.
 * This implementation is designed for space efficiency more than
 * raw speed.
 */

__constant uint sha2_init[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint sha2_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void
sha2_256_init(uint *out)
{
#define sha2_256_init_inner_1(i) \
	out[i] = sha2_init[i];

	hash256_unroll(sha2_256_init_inner_1);
}

/* The state variable remapping is really contorted */
#define sha2_stvar(vals, i, v) vals[(64+v-i) % 8]
#define sha2_s0(a) (rotate(a, 30U) ^ rotate(a, 19U) ^ rotate(a, 10U))
#define sha2_s1(a) (rotate(a, 26U) ^ rotate(a, 21U) ^ rotate(a, 7U))
#if defined(AMD_BFI_INT)
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define sha2_ch(a, b, c) amd_bytealign(a, b, c)
#define sha2_ma(a, b, c) amd_bytealign((a^c), b, a)
#else
#define sha2_ch(a, b, c) (c ^ (a & (b ^ c)))
#define sha2_ma(a, b, c) ((a & c) | (b & (a | c)))
#endif

void
sha2_256_block(uint *out, uint *in)
{
	uint state[8], t1, t2;
#if defined(PRAGMA_UNROLL)
	int i;
#endif

#define sha2_256_block_inner_1(i) \
	state[i] = out[i];
	hash256_unroll(sha2_256_block_inner_1);

#define sha2_256_block_inner_2(i) \
	if (i >= 16) {							\
		t1 = in[(i + 1) % 16];					\
		t2 = in[(i + 14) % 16];					\
		in[i % 16] += (in[(i + 9) % 16] +			\
		       (rotate(t1, 25U) ^ rotate(t1, 14U) ^ (t1 >> 3)) + \
		       (rotate(t2, 15U) ^ rotate(t2, 13U) ^ (t2 >> 10))); \
	}								\
	t1 = (sha2_stvar(state, i, 7) +					\
	      sha2_s1(sha2_stvar(state, i, 4)) +			\
	      sha2_ch(sha2_stvar(state, i, 4),				\
		      sha2_stvar(state, i, 5),				\
		      sha2_stvar(state, i, 6)) +			\
	      sha2_k[i] +						\
	      in[i % 16]);						\
	t2 = (sha2_s0(sha2_stvar(state, i, 0)) +			\
	      sha2_ma(sha2_stvar(state, i, 0),				\
		      sha2_stvar(state, i, 1),				\
		      sha2_stvar(state, i, 2)));			\
	sha2_stvar(state, i, 3) += t1;					\
	sha2_stvar(state, i, 7) = t1 + t2;				\

#if !defined(PRAGMA_UNROLL)
	iter_64(sha2_256_block_inner_2);
#else
#pragma unroll 64
	for (i = 0; i < 64; i++) { sha2_256_block_inner_2(i) }
#endif

#define sha2_256_block_inner_3(i) \
	out[i] += state[i];

	hash256_unroll(sha2_256_block_inner_3);
}


/*
 * RIPEMD160
 *
 * Data expected in little-endian format.
 */

__constant uint ripemd160_iv[] = {
	0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
__constant uint ripemd160_k[] = {
	0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
__constant uint ripemd160_kp[] = {
	0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };
__constant uchar ripemd160_ws[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
};
__constant uchar ripemd160_wsp[] = {
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};
__constant uchar ripemd160_rl[] = {
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
};
__constant uchar ripemd160_rlp[] = {
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

#define ripemd160_val(v, i, n) (v)[(80+(n)-(i)) % 5]
#define ripemd160_valp(v, i, n) (v)[5 + ((80+(n)-(i)) % 5)]
#if defined(AMD_BFI_INT)
#define ripemd160_f0(x, y, z) (x ^ y ^ z)
#define ripemd160_f1(x, y, z) amd_bytealign(x, y, z)
#define ripemd160_f2(x, y, z) (z ^ (x | ~y))
#define ripemd160_f3(x, y, z) amd_bytealign(z, x, y)
#define ripemd160_f4(x, y, z) (x ^ (y | ~z))
#else
#define ripemd160_f0(x, y, z) (x ^ y ^ z)
#define ripemd160_f1(x, y, z) ((x & y) | (~x & z))
#define ripemd160_f2(x, y, z) (z ^ (x | ~y))
#define ripemd160_f3(x, y, z) ((x & z) | (y & ~z))
#define ripemd160_f4(x, y, z) (x ^ (y | ~z))
#endif
#define ripemd160_round(i, in, vals, f, fp, t) do {			\
		ripemd160_val(vals, i, 0) =				\
			rotate(ripemd160_val(vals, i, 0) +		\
			       f(ripemd160_val(vals, i, 1),		\
				 ripemd160_val(vals, i, 2),		\
				 ripemd160_val(vals, i, 3)) +		\
			       in[ripemd160_ws[i]] +			\
			       ripemd160_k[i / 16],			\
			       (uint)ripemd160_rl[i]) +			\
			ripemd160_val(vals, i, 4);			\
		ripemd160_val(vals, i, 2) =				\
			rotate(ripemd160_val(vals, i, 2), 10U);		\
		ripemd160_valp(vals, i, 0) =				\
			rotate(ripemd160_valp(vals, i, 0) +		\
			       fp(ripemd160_valp(vals, i, 1),		\
				  ripemd160_valp(vals, i, 2),		\
				  ripemd160_valp(vals, i, 3)) +		\
			       in[ripemd160_wsp[i]] +			\
			       ripemd160_kp[i / 16],			\
			       (uint)ripemd160_rlp[i]) +		\
			ripemd160_valp(vals, i, 4);			\
		ripemd160_valp(vals, i, 2) =				\
			rotate(ripemd160_valp(vals, i, 2), 10U);	\
	} while (0)

void
ripemd160_init(uint *out)
{
#define ripemd160_init_inner_1(i) \
	out[i] = ripemd160_iv[i];

	hash160_unroll(ripemd160_init_inner_1);
}

void
ripemd160_block(uint *out, uint *in)
{
	uint vals[10], t;
#if defined(PRAGMA_UNROLL)
	int i;
#endif

#define ripemd160_block_inner_1(i) \
	vals[i] = vals[i + 5] = out[i];

	hash160_unroll(ripemd160_block_inner_1);

#define ripemd160_block_inner_p0(i)		\
	ripemd160_round(i, in, vals, \
			ripemd160_f0, ripemd160_f4, t);
#define ripemd160_block_inner_p1(i)		\
	ripemd160_round((16 + i), in, vals,		\
			ripemd160_f1, ripemd160_f3, t);
#define ripemd160_block_inner_p2(i)		\
	ripemd160_round((32 + i), in, vals,		\
			ripemd160_f2, ripemd160_f2, t);
#define ripemd160_block_inner_p3(i)		\
	ripemd160_round((48 + i), in, vals,		\
			ripemd160_f3, ripemd160_f1, t);
#define ripemd160_block_inner_p4(i)		\
	ripemd160_round((64 + i), in, vals,		\
			ripemd160_f4, ripemd160_f0, t);

#if !defined(PRAGMA_UNROLL)
	iter_16(ripemd160_block_inner_p0);
	iter_16(ripemd160_block_inner_p1);
	iter_16(ripemd160_block_inner_p2);
	iter_16(ripemd160_block_inner_p3);
	iter_16(ripemd160_block_inner_p4);
#else
#pragma unroll 16
	for (i = 0; i < 16; i++) { ripemd160_block_inner_p0(i); }
#pragma unroll 16
	for (i = 0; i < 16; i++) { ripemd160_block_inner_p1(i); }
#pragma unroll 16
	for (i = 0; i < 16; i++) { ripemd160_block_inner_p2(i); }
#pragma unroll 16
	for (i = 0; i < 16; i++) { ripemd160_block_inner_p3(i); }
#pragma unroll 16
	for (i = 0; i < 16; i++) { ripemd160_block_inner_p4(i); }
#endif

	t = out[1] + vals[2] + vals[8];
	out[1] = out[2] + vals[3] + vals[9];
	out[2] = out[3] + vals[4] + vals[5];
	out[3] = out[4] + vals[0] + vals[6];
	out[4] = out[0] + vals[1] + vals[7];
	out[0] = t;
}


#ifdef TEST_KERNELS
/*
 * Test kernels
 */

/* Montgomery multiplication test kernel */
__kernel void
test_mul_mont(__global bignum *products_out, __global bignum *nums_in)
{
	bignum a, b, c;
	int o;
	o = get_global_id(0);
	nums_in += (2*o);

	a = nums_in[0];
	b = nums_in[1];
	bn_mul_mont(&c, &a, &b);
	products_out[o] = c;
}

/* modular inversion test kernel */
__kernel void
test_mod_inverse(__global bignum *inv_out, __global bignum *nums_in,
		 int count)
{
	bignum x, xp;
	int i, o;
	o = get_global_id(0) * count;
	for (i = 0; i < count; i++) {
		x = nums_in[o];
		bn_mod_inverse(&xp, &x);
		inv_out[o++] = xp;
	}
}
#endif  /* TEST_KERNELS */


#define ACCESS_BUNDLE 1024
#define ACCESS_STRIDE (ACCESS_BUNDLE/BN_NWORDS)

__kernel void
ec_add_grid(__global bn_word *points_out, __global bn_word *z_heap, 
	    __global bn_word *row_in, __global bignum *col_in)
{
	bignum rx, ry;
	bignum x1, y1, a, b, c, d, e, z;
	bn_word cy;
	int i, cell, start;

	/* Load the row increment point */
	i = 2 * get_global_id(1);
	rx = col_in[i];
	ry = col_in[i+1];

	cell = get_global_id(0);
	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));

#define ec_add_grid_inner_1(i) \
	x1.d[i] = row_in[start + (i*ACCESS_STRIDE)];

	bn_unroll(ec_add_grid_inner_1);
	start += (ACCESS_STRIDE/2);

#define ec_add_grid_inner_2(i) \
	y1.d[i] = row_in[start + (i*ACCESS_STRIDE)];

	bn_unroll(ec_add_grid_inner_2);

	bn_mod_sub(&z, &x1, &rx);

	cell += (get_global_id(1) * get_global_size(0));
	start = (((cell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % ACCESS_STRIDE));

#define ec_add_grid_inner_3(i) \
	z_heap[start + (i*ACCESS_STRIDE)] = z.d[i];

	bn_unroll(ec_add_grid_inner_3);

	bn_mod_sub(&b, &y1, &ry);
	bn_mod_add(&c, &x1, &rx);
	bn_mod_add(&d, &y1, &ry);
	bn_mul_mont(&y1, &b, &b);
	bn_mul_mont(&x1, &z, &z);
	bn_mul_mont(&e, &c, &x1);
	bn_mod_sub(&y1, &y1, &e);

	/*
	 * This disgusting code caters to the global memory unit on
	 * various GPUs, by giving it a nice contiguous patch to write
	 * per warp/wavefront.
	 */
	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));

#define ec_add_grid_inner_4(i) \
	points_out[start + (i*ACCESS_STRIDE)] = y1.d[i];

	bn_unroll(ec_add_grid_inner_4);

	bn_mod_lshift1(&y1);
	bn_mod_sub(&y1, &e, &y1);
	bn_mul_mont(&y1, &y1, &b);
	bn_mul_mont(&a, &x1, &z);
	bn_mul_mont(&c, &d, &a);
	bn_mod_sub(&y1, &y1, &c);
	cy = 0;
	if (bn_is_odd(y1))
		cy = bn_uadd_c(&y1, &y1, modulus);
	bn_rshift1(&y1);
	y1.d[BN_NWORDS-1] |= (cy ? 0x80000000 : 0);

	start += (ACCESS_STRIDE/2);

	bn_unroll(ec_add_grid_inner_4);
}

__kernel void
heap_invert(__global bn_word *z_heap, int batch)
{
	bignum a, b, c, z;
	int i, off, lcell, hcell, start;

#define heap_invert_inner_load_a(j)				\
		a.d[j] = z_heap[start + j*ACCESS_STRIDE];
#define heap_invert_inner_load_b(j)				\
		b.d[j] = z_heap[start + j*ACCESS_STRIDE];
#define heap_invert_inner_load_z(j)				\
		z.d[j] = z_heap[start + j*ACCESS_STRIDE];
#define heap_invert_inner_store_z(j)				\
		z_heap[start + j*ACCESS_STRIDE] = z.d[j];
#define heap_invert_inner_store_c(j)				\
		z_heap[start + j*ACCESS_STRIDE] = c.d[j];

	off = get_global_size(0);
	lcell = get_global_id(0);
	hcell = (off * batch) + lcell;
	for (i = 0; i < (batch-1); i++) {

		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));

		bn_unroll(heap_invert_inner_load_a);

		lcell += off;
		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));

		bn_unroll(heap_invert_inner_load_b);

		bn_mul_mont(&z, &a, &b);

		start = (((hcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (hcell % ACCESS_STRIDE));

		bn_unroll(heap_invert_inner_store_z);

		lcell += off;
		hcell += off;
	}

	/* Invert the root, fix up 1/ZR -> R/Z */
	bn_mod_inverse(&z, &z);

#define heap_invert_inner_1(i)			\
	a.d[i] = mont_rr[i];

	bn_unroll(heap_invert_inner_1);

	bn_mul_mont(&z, &z, &a);
	bn_mul_mont(&z, &z, &a);

	/* Unroll the first iteration to avoid a load/store on the root */
	lcell -= (off << 1);
	hcell -= (off << 1);

	start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (lcell % ACCESS_STRIDE));
	bn_unroll(heap_invert_inner_load_a);

	lcell += off;
	start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (lcell % ACCESS_STRIDE));
	bn_unroll(heap_invert_inner_load_b);

	bn_mul_mont(&c, &a, &z);

	bn_unroll(heap_invert_inner_store_c);

	bn_mul_mont(&c, &b, &z);

	lcell -= off;
	start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (lcell % ACCESS_STRIDE));
	bn_unroll(heap_invert_inner_store_c);

	lcell -= (off << 1);

	for (i = 0; i < (batch-2); i++) {
		start = (((hcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (hcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_load_z);

		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_load_a);

		lcell += off;
		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_load_b);

		bn_mul_mont(&c, &a, &z);

		bn_unroll(heap_invert_inner_store_c);

		bn_mul_mont(&c, &b, &z);

		lcell -= off;
		start = (((lcell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
			 (lcell % ACCESS_STRIDE));
		bn_unroll(heap_invert_inner_store_c);

		lcell -= (off << 1);
		hcell -= off;
	}
}

void
hash_ec_point(uint *hash_out, __global bn_word *xy, __global bn_word *zip)
{
	uint hash1[16], hash2[16];
	bignum c, zi, zzi;
	bn_word wh, wl;

	/*
	 * Multiply the coordinates by the inverted Z values.
	 * Stash the coordinates in the hash buffer.
	 * SHA-2 requires big endian, and our intended hash input
	 * is big-endian, so swapping is unnecessary, but
	 * inserting the format byte in front causes a headache.
	 */
#define hash_ec_point_inner_1(i)		\
	zi.d[i] = zip[i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_1);

	bn_mul_mont(&zzi, &zi, &zi);  /* 1 / Z^2 */

#define hash_ec_point_inner_2(i)		\
	c.d[i] = xy[i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_2);

	bn_mul_mont(&c, &c, &zzi);  /* X / Z^2 */
	bn_from_mont(&c, &c);

	wh = 0x00000004;  /* POINT_CONVERSION_UNCOMPRESSED */

#define hash_ec_point_inner_3(i)		\
	wl = wh;				\
	wh = c.d[(BN_NWORDS - 1) - i];		\
	hash1[i] = (wl << 24) | (wh >> 8);

	bn_unroll(hash_ec_point_inner_3);

	bn_mul_mont(&zzi, &zzi, &zi);  /* 1 / Z^3 */

#define hash_ec_point_inner_4(i)				\
	c.d[i] = xy[(ACCESS_STRIDE/2) + i*ACCESS_STRIDE];

	bn_unroll(hash_ec_point_inner_4);

	bn_mul_mont(&c, &c, &zzi);  /* Y / Z^3 */
	bn_from_mont(&c, &c);

#define hash_ec_point_inner_5(i)			\
	wl = wh;					\
	wh = c.d[(BN_NWORDS - 1) - i];			\
	hash1[BN_NWORDS + i] = (wl << 24) | (wh >> 8);

	bn_unroll(hash_ec_point_inner_5);

	/*
	 * Hash the first 64 bytes of the buffer
	 */
	sha2_256_init(hash2);
	sha2_256_block(hash2, hash1);

	/*
	 * Hash the last byte of the buffer + SHA-2 padding
	 */
	hash1[0] = wh << 24 | 0x800000;
	hash1[1] = 0;
	hash1[2] = 0;
	hash1[3] = 0;
	hash1[4] = 0;
	hash1[5] = 0;
	hash1[6] = 0;
	hash1[7] = 0;
	hash1[8] = 0;
	hash1[9] = 0;
	hash1[10] = 0;
	hash1[11] = 0;
	hash1[12] = 0;
	hash1[13] = 0;
	hash1[14] = 0;
	hash1[15] = 65 * 8;
	sha2_256_block(hash2, hash1);

	/*
	 * Hash the SHA-2 result with RIPEMD160
	 * Unfortunately, SHA-2 outputs big-endian, but
	 * RIPEMD160 expects little-endian.  Need to swap!
	 */

#define hash_ec_point_inner_6(i)		\
	hash2[i] = bswap32(hash2[i]);

	hash256_unroll(hash_ec_point_inner_6);

	hash2[8] = bswap32(0x80000000);
	hash2[9] = 0;
	hash2[10] = 0;
	hash2[11] = 0;
	hash2[12] = 0;
	hash2[13] = 0;
	hash2[14] = 32 * 8;
	hash2[15] = 0;
	ripemd160_init(hash_out);
	ripemd160_block(hash_out, hash2);
}


__kernel void
hash_ec_point_get(__global uint *hashes_out,
		  __global bn_word *points_in, __global bn_word *z_heap)
{
	uint hash[5];
	int i, p, cell, start;

	cell = ((get_global_id(1) * get_global_size(0)) + get_global_id(0));
	start = (((cell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % ACCESS_STRIDE));
	z_heap += start;

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));
	points_in += start;

	/* Complete the coordinates and hash */
	hash_ec_point(hash, points_in, z_heap);

	p = get_global_size(0);
	i = p * get_global_id(1);
	hashes_out += 5 * (i + get_global_id(0));

	/* Output the hash in proper byte-order */
#define hash_ec_point_get_inner_1(i)		\
	hashes_out[i] = load_le32(hash[i]);

	hash160_unroll(hash_ec_point_get_inner_1);
}

/*
 * Normally this would be one function that compared two hash160s.
 * This one compares a hash160 with an upper and lower bound in one
 * function to work around a problem with AMD's OpenCL compiler.
 */
int
hash160_ucmp_g(uint *a, __global uint *bound)
{
	uint gv;

#define hash160_ucmp_g_inner_1(i) 		\
		gv = load_be32(bound[i]);	\
		if (a[i] < gv) return -1;	\
		if (a[i] > gv) break;

	hash160_iter(hash160_ucmp_g_inner_1);

#define hash160_ucmp_g_inner_2(i)   		\
		gv = load_be32(bound[5+i]);	\
		if (a[i] < gv) return 0;	\
		if (a[i] > gv) return 1;

	hash160_iter(hash160_ucmp_g_inner_2);
	return 0;
}

__kernel void
hash_ec_point_search_prefix(__global uint *found,
			    __global bn_word *points_in,
			    __global bn_word *z_heap,
			    __global uint *target_table, int ntargets)
{
	uint hash[5];
	int i, high, low, p, cell, start;

	cell = ((get_global_id(1) * get_global_size(0)) + get_global_id(0));
	start = (((cell / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % ACCESS_STRIDE));
	z_heap += start;

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));
	points_in += start;

	/* Complete the coordinates and hash */
	hash_ec_point(hash, points_in, z_heap);

	/*
	 * Unconditionally byteswap the hash result, because:
	 * - The byte-level convention of RIPEMD160 is little-endian
	 * - We are comparing it in big-endian order
	 */
#define hash_ec_point_search_prefix_inner_1(i)	\
	hash[i] = bswap32(hash[i]);

	hash160_unroll(hash_ec_point_search_prefix_inner_1);

	/* Binary-search the target table for the hash we just computed */
	for (high = ntargets - 1, low = 0, i = high >> 1;
	     high >= low;
	     i = low + ((high - low) >> 1)) {
		p = hash160_ucmp_g(hash, &target_table[10*i]);
		low = (p > 0) ? (i + 1) : low;
		high = (p < 0) ? (i - 1) : high;
		if (p == 0) {
			/* For debugging purposes, write the hash value */
			found[0] = ((get_global_id(1) * get_global_size(0)) +
				    get_global_id(0));
			found[1] = i;

#define hash_ec_point_search_prefix_inner_2(i)	\
			found[i+2] = load_be32(hash[i]);

			hash160_unroll(hash_ec_point_search_prefix_inner_2);
			high = -1;
		}
	}
}
