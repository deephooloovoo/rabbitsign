/*
 * RabbitSign - Tools for signing TI graphing calculator software
 * Copyright (C) 2009 Benjamin Moody
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_ASSERT_H
# include <assert.h>
#else
# define assert(xxx) if (!(xxx)) {				\
    fprintf(stderr, "mpz: assertion \"%s\" failed\n", #xxx);	\
    abort();							\
  }
#endif

#include "mpz.h"

/*
 * This file contains multiple-precision arithmetic functions.  These
 * are equivalent to the corresponding GMP functions in the ways they
 * are used by RabbitSign.
 *
 * HOWEVER, they are not by any means complete.  They do not meet the
 * specifications of the GMP functions; for the sake of portability
 * and compactness they are vastly less efficient; and they may even
 * have bugs.
 */

/*
#define DBG(args...) if (1) \
  do { \
    gmp_fprintf(stderr, "mpz: " args); \
    fputc('\n', stderr); \
  } while (0)
*/

#define IDX(nnn, iii) (nnn)->m[iii]

/* \
  (*(__extension__ ({ \
      int _ii = (iii); \
      const struct _mpz* _nn = (nnn); \
      assert(_nn->size <= _nn->size_alloc); \
      assert(_ii >= 0); \
      assert(((unsigned) _ii) < (_nn->size)); \
      &(_nn->m[_ii]); })))
*/

static void* xrealloc(p, n)
     void* p;
     size_t n;
{
  void* res;

  if (n <= 0)
    n = 1;

  if (p)
    res = realloc(p, n);
  else
    res = malloc(n);

  if (!res) {
    fprintf(stderr,"mpz: out of memory (need %lu bytes)\n",
	    (unsigned long) n);
    abort();
  }
  return res;
}

static inline void allocate_mpz(x)
     mpz_t x;
{
  if (x->size_alloc < x->size) {
    x->size_alloc = x->size;
    x->m = (limb_t*) xrealloc(x->m, x->size_alloc * sizeof(limb_t));
  }
}

static inline void zero_mpz(x)
     mpz_t x;
{
  size_t i;
  for (i = 0; i < x->size; i++)
    IDX(x, i) = 0;
}

static inline void copyref_mpz(dest, src)
     mpz_t dest;
     const mpz_t src;
{
  dest->size = src->size;
  dest->size_alloc = src->size_alloc;
  dest->m = src->m;
  dest->sign = src->sign;
}

static inline void reduce_mpz(x)
     mpz_t x;
{
  while (x->size > 0 && IDX(x, (x->size) - 1) == 0)
    x->size--;
}

/**************** Init / Clear ****************/

void mpz_init(x)
     mpz_t x;
{
  x->size = 0;
  x->size_alloc = 0;
  x->m = (limb_t*)0;
  x->sign = 1;
}

void mpz_clear(x)
     mpz_t x;
{
  if (x->m)
    free(x->m);
  mpz_init(x);
}

/**************** Setting ****************/

void mpz_set(dest, src)
     mpz_t dest;
     const mpz_t src;
{
  size_t i;

  dest->size = src->size;
  allocate_mpz(dest);
  dest->sign = src->sign;

  for (i = 0; i < src->size; i++)
    IDX(dest, i) = IDX(src, i);
}

void mpz_set_ui(dest, a)
     mpz_t dest;
     unsigned int a;
{
  if (a) {
    dest->size = 1;
    allocate_mpz(dest);
    IDX(dest, 0) = a;
  }
  else
    dest->size = 0;
  dest->sign = 1;
}

unsigned int mpz_get_ui(a)
     const mpz_t a;
{
  return IDX(a, 0);
}

static void mpz_swap(a, b)
     mpz_t a;
     mpz_t b;
{
  mpz_t temp;
  copyref_mpz(temp, a);
  copyref_mpz(a, b);
  copyref_mpz(b, temp);
}

/**************** Import / Export ****************/

void mpz_import(dest, count, order, size, endian, nails, op)
     mpz_t dest;
     size_t count;
     int order; /* must be -1 (little endian structure) */
     int size; /* must be 1 (bytes) */
     int endian; /* must be 0 (native endian words, doesn't matter for bytes) */
     size_t nails; /* must be 0 (no nails) */
     const void* op;
{
  size_t i, j;

  assert(order == -1);
  assert(size == 1);
  assert(endian == 0);
  assert(nails == 0);

  dest->size = (count + LIMB_BYTES - 1) / LIMB_BYTES;
  allocate_mpz(dest);
  dest->sign = 1;

  for (i = 0; i < dest->size; i++) {
    IDX(dest, i) = 0;
    for (j = 0; j < LIMB_BYTES && ((i * LIMB_BYTES) + j) < count; j++) {
      IDX(dest, i) |= ((unsigned char*)op)[(i * LIMB_BYTES) + j] << 8 * j;
    }
  }
}

void mpz_export(dest, count, order, size, endian, nails, op)
     void* dest;
     size_t* count;
     int order; /* must be -1 (little endian structure) */
     int size; /* must be 1 (bytes) */
     int endian; /* must be 0 (native endian words, doesn't matter for bytes) */
     size_t nails; /* must be 0 (no nails) */
     const mpz_t op;
{
  size_t i, j;

  assert(order == -1);
  assert(size == 1);
  assert(endian == 0);
  assert(nails == 0);

  for (i = 0; i < op->size; i++) {
    for (j = 0; j < LIMB_BYTES; j++) {
      ((unsigned char*)dest)[(i * LIMB_BYTES) + j] = IDX(op, i) >> 8 * j;
    }
  }
  *count = op->size * LIMB_BYTES;
}

/**************** Comparison ****************/

int mpz_sgn(a)
     const mpz_t a;
{
  size_t i = a->size;

  while (i > 0 && IDX(a, i - 1) == 0)
    i--;

  if (i == 0)
    return 0;
  else
    return a->sign;
}

static int mpz_cmpabs(a, b)
     const mpz_t a;
     const mpz_t b;
{
  size_t sa = a->size;
  size_t sb = b->size;

  while (sa > 0 && IDX(a, sa - 1) == 0)
    sa--;
  while (sb > 0 && IDX(b, sb - 1) == 0)
    sb--;

  if (sa > sb)
    return 1;
  else if (sb > sa)
    return -1;

  while (sa > 0) {
    if (IDX(a, sa - 1) > IDX(b, sa - 1))
      return 1;
    else if (IDX(a, sa - 1) < IDX(b, sa - 1))
      return -1;
    sa--;
  }

  return 0;
}

int mpz_cmp(a, b)
     const mpz_t a;
     const mpz_t b;
{
  size_t sa = a->size;
  size_t sb = b->size;

  while (sa > 0 && IDX(a, sa - 1) == 0)
    sa--;
  while (sb > 0 && IDX(b, sb - 1) == 0)
    sb--;

  if (sa == 0 && sb == 0)
    return 0;
  else if (sa == 0)
    return -(b->sign);
  else if (sb == 0)
    return a->sign;
  else if (a->sign != b->sign)
    return a->sign;

  return a->sign * mpz_cmpabs(a, b);
}

int mpz_cmp_ui(a, b)
     const mpz_t a;
     unsigned int b;
{
  size_t sa = a->size;

  while (sa > 0 && IDX(a, sa - 1) == 0)
    sa--;

  if (sa == 0 && b == 0)
    return 0;

  if (sa == 1 && a->sign == 1) {
    if (IDX(a, 0) > b)
      return 1;
    else if (IDX(a, 0) < b)
      return -1;
    else
      return 0;
  }

  return (a->sign);
}

/**************** Addition / Subtraction ****************/

static void mpz_addabs(dest, a, b)
     mpz_t dest;		/* != a, b */
     const mpz_t a;
     const mpz_t b;
{
  size_t i;
  double_limb_t carry = 0;

  if (a->size > b->size)
    dest->size = a->size + 1;
  else
    dest->size = b->size + 1;
  allocate_mpz(dest);

  assert(dest != a);
  assert(dest != b);

  for (i = 0; i < a->size && i < b->size; i++) {
    carry += IDX(a, i);
    carry += IDX(b, i);
    IDX(dest, i) = carry & LIMB_MASK;
    carry >>= LIMB_BITS;
  }

  for (; i < a->size; i++) {
    carry += IDX(a, i);
    IDX(dest, i) = carry & LIMB_MASK;
    carry >>= LIMB_BITS;
  }

  for (; i < b->size; i++) {
    carry += IDX(b, i);
    IDX(dest, i) = carry & LIMB_MASK;
    carry >>= LIMB_BITS;
  }
  IDX(dest, i) = carry;
}

static void mpz_subabs(dest, a, b)
     mpz_t dest;		/* != b */
     const mpz_t a;
     const mpz_t b;		/* must be <= a */
{
  size_t i;
  signed_double_limb_t carry = 0;
  dest->size = a->size;
  allocate_mpz(dest);

  assert(dest != b);

  for (i = 0; i < a->size && i < b->size; i++) {
    carry += IDX(a, i);
    carry -= IDX(b, i);
    IDX(dest, i) = carry & LIMB_MASK;
    carry >>= LIMB_BITS;
  }

  for (; i < a->size; i++) {
    carry += IDX(a, i);
    IDX(dest, i) = carry & LIMB_MASK;
    carry >>= LIMB_BITS;
  }

  assert(carry == 0);
}

void mpz_add(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     const mpz_t b;
{
  mpz_t temp;
  mpz_init(temp);

  if (a->sign == b->sign) {
    temp->sign = a->sign;
    mpz_addabs(temp, a, b);
  }
  else if (mpz_cmpabs(a, b) > 0) {
    temp->sign = a->sign;
    mpz_subabs(temp, a, b);
  }
  else {
    temp->sign = b->sign;
    mpz_subabs(temp, b, a);
  }

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

void mpz_sub(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     const mpz_t b;
{
  mpz_t temp;
  mpz_init(temp);

  if (a->sign != b->sign) {
    temp->sign = a->sign;
    mpz_addabs(temp, a, b);
  }
  else if (mpz_cmpabs(a, b) > 0) {
    temp->sign = a->sign;
    mpz_subabs(temp, a, b);
  }
  else {
    temp->sign = -(b->sign);
    mpz_subabs(temp, b, a);
  }

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

void mpz_add_ui(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     unsigned int b;
{
  size_t i;
  mpz_t temp;
  mpz_init(temp);

  temp->size = a->size + 1;
  temp->sign = a->sign;
  allocate_mpz(temp);

  for (i = 0; i < a->size; i++) {
    IDX(temp, i) = IDX(a, i) + b;
    b = (IDX(temp, i) < IDX(a, i)) ? 1 : 0;
  }
  IDX(temp, i) = b;

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

void mpz_sub_ui(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     unsigned int b;
{
  size_t i;
  mpz_t temp;
  mpz_init(temp);

  temp->size = a->size;
  temp->sign = a->sign;
  allocate_mpz(temp);

  for (i = 0; i < a->size; i++) {
    IDX(temp, i) = IDX(a, i) - b;
    b = (IDX(temp, i) > IDX(a, i)) ? 1 : 0;
  }
  assert(b == 0);

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

/**************** Multiplication ****************/

void mpz_mul(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     const mpz_t b;
{
  double_limb_t carry = 0, newcarry;
  size_t i, j, k;
  mpz_t temp;
  mpz_init(temp);

  temp->size = a->size + b->size;
  temp->sign = a->sign * b->sign;
  allocate_mpz(temp);
  zero_mpz(temp);

  for (i = 0; i < a->size; i++) {
    for (j = 0; j < b->size; j++) {
      carry = IDX(a, i);
      carry *= IDX(b, j);
      for (k = i + j; k < temp->size && carry; k++) {
	newcarry = carry + IDX(temp, k);
	if (newcarry < carry) {
	  IDX(temp, k) = newcarry & LIMB_MASK;
	  carry = (newcarry >> LIMB_BITS) + LIMB_MASK + 1;
	}
	else {
	  IDX(temp, k) = newcarry & LIMB_MASK;
	  carry = (newcarry >> LIMB_BITS);
	}
      }
      assert(carry == 0);
    }
  }

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

void mpz_mul_ui(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     unsigned int b;		/* must be fairly small */
{
  double_limb_t carry = 0;
  size_t i;
  mpz_t temp;
  mpz_init(temp);

  temp->size = a->size + 1;
  temp->sign = a->sign;
  allocate_mpz(temp);

  for (i = 0; i < a->size; i++) {
    carry += (double_limb_t) IDX(a, i) * b;
    IDX(temp, i) = carry & LIMB_MASK;
    carry >>= LIMB_BITS;
  }
  IDX(temp, i) = carry & LIMB_MASK;

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

/**************** Division ****************/

void mpz_fdiv_q_2exp(dest, a, b)
     mpz_t dest;
     const mpz_t a;
     unsigned int b;		/* must be <= LIMB_BITS */
{
  size_t i;
  mpz_t temp;
  mpz_init(temp);

  assert(b <= LIMB_BITS);

  temp->size = a->size;
  temp->sign = a->sign;
  allocate_mpz(temp);

  if (a->size > 0) {
    for (i = 0; i < (a->size - 1); i++) {
      IDX(temp, i) = (((IDX(a, i) >> b) | (IDX(a, i + 1) << (LIMB_BITS - b)))
		      & LIMB_MASK);
    }
    IDX(temp, a->size - 1) = IDX(a, a->size - 1) >> b;
  }

  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

/**************** Division / Modulus ****************/

static void mpz_setbit(dest, n)
     mpz_t dest;
     unsigned int n;
{
  size_t i, j;

  i = n / LIMB_BITS + 1;

  if (dest->size < i) {
    j = dest->size;
    dest->size = i;
    allocate_mpz(dest);
    while (j < i) {
      IDX(dest, j) = 0;
      j++;
    }
  }

  IDX(dest, i - 1) |= (1 << (n % LIMB_BITS));
}

static void mpz_fdiv_qr(q, r, num, den)
     mpz_t q;
     mpz_t r;
     const mpz_t num;
     const mpz_t den;
{
  size_t shiftct = 0;
  size_t i;
  mpz_t remainder;
  mpz_t quotient;
  mpz_t shifted;		/* shifted = mod * 2^(shiftct) */

  mpz_init(remainder);
  mpz_init(shifted);
  if (q) {
    mpz_init(quotient);
    quotient->sign = num->sign * den->sign;
  }

  shifted->size = num->size;
  allocate_mpz(shifted);

  mpz_set(remainder, num);
  mpz_set(shifted, den);

  reduce_mpz(shifted);
  assert(shifted->size > 0);

  while (mpz_cmpabs(remainder, shifted) > 0) {
    shifted->size++;
    allocate_mpz(shifted);
    for (i = shifted->size - 1; i > 0; i--)
      IDX(shifted, i) = IDX(shifted, i - 1);
    IDX(shifted, 0) = 0;
    shiftct += LIMB_BITS;
  }

  while (shiftct != 0) {
    if (mpz_cmpabs(remainder, shifted) >= 0) {
      mpz_subabs(remainder, remainder, shifted);
      reduce_mpz(remainder);
      if (q)
	mpz_setbit(quotient, shiftct);
    }
    mpz_fdiv_q_2exp(shifted, shifted, 1);
    shiftct--;
  }

  if (mpz_cmpabs(remainder, den) >= 0) {
    mpz_subabs(remainder, remainder, den);
    if (q)
      mpz_setbit(quotient, 0);
  }

  if (mpz_sgn(remainder) == -1) {
    mpz_add(remainder, remainder, den);
    if (q)
      mpz_sub_ui(quotient, quotient, 1);
  }

  mpz_clear(shifted);
  reduce_mpz(remainder);
  mpz_clear(r);
  copyref_mpz(r, remainder);

  if (q) {
    reduce_mpz(quotient);
    mpz_clear(q);
    copyref_mpz(q, quotient);
  }
}

void mpz_mod(dest, a, mod)
     mpz_t dest;
     const mpz_t a;
     const mpz_t mod;
{
  mpz_fdiv_qr(NULL, dest, a, mod);
}

/**************** Modular exponent ****************/

void mpz_powm(dest, base, exp, mod)
     mpz_t dest;
     const mpz_t base;
     const mpz_t exp;
     const mpz_t mod;
{
  mpz_t exp_bits;
  mpz_t base_power;
  mpz_t temp;
  mpz_init(exp_bits);
  mpz_init(base_power);
  mpz_init(temp);

  mpz_set(exp_bits, exp);
  mpz_set(base_power, base);
  mpz_set_ui(temp, 1);

  reduce_mpz(exp_bits);
  assert(exp_bits->sign == 1 || exp_bits->size == 0);

  while (exp_bits->size > 0) {
    if (IDX(exp_bits, 0) & 1) {
      mpz_mul(temp, temp, base_power);
      mpz_mod(temp, temp, mod);
    }
    mpz_mul(base_power, base_power, base_power);
    mpz_mod(base_power, base_power, mod);
    mpz_fdiv_q_2exp(exp_bits, exp_bits, 1);
  }

  mpz_clear(exp_bits);
  mpz_clear(base_power);
  reduce_mpz(temp);
  mpz_clear(dest);
  copyref_mpz(dest, temp);
}

/**************** Legendre symbol ****************/

int mpz_legendre(a, p)
     const mpz_t a;
     const mpz_t p;
{
  int x;
  mpz_t exp;
  mpz_t pow;
  mpz_init(exp);
  mpz_init(pow);

  mpz_set(exp, p);
  mpz_sub_ui(exp, exp, 1);
  mpz_fdiv_q_2exp(exp, exp, 1);
  mpz_powm(pow, a, exp, p);

  if (pow->size == 1 && IDX(pow, 0) == 1)
    x = 1;
  else if (pow->size == 0)
    x = 0;
  else
    x = -1;

  mpz_clear(exp);
  mpz_clear(pow);

  return x;
}

/**************** GCD ****************/

static void mpz_gcdext_main(g, ai, bi, a, b)
     mpz_t g;
     mpz_t ai;
     mpz_t bi;
     const mpz_t a;
     const mpz_t b;
{
  mpz_t rem_last, rem_cur;
  mpz_t ai_last, ai_cur;
  mpz_t bi_last, bi_cur;
  mpz_t q, temp;

  mpz_init(rem_last);
  mpz_init(rem_cur);
  mpz_init(q);

  mpz_set(rem_last, a);
  mpz_set(rem_cur, b);

  if (ai) {
    mpz_init(ai_last);
    mpz_init(ai_cur);
    mpz_set_ui(ai_last, 1);
  }

  if (bi) {
    mpz_init(bi_last);
    mpz_init(bi_cur);
    mpz_set_ui(bi_cur, 1);
  }

  assert(a->sign == 1 && a->size > 0);
  assert(b->sign == 1 && b->size > 0);

  while (1) {
    mpz_fdiv_qr(q, rem_last, rem_last, rem_cur);
    mpz_swap(rem_last, rem_cur);
    if (!mpz_sgn(rem_cur))
      break;

    if (ai) {
      mpz_init(temp);
      mpz_mul(temp, q, ai_cur);
      mpz_sub(temp, ai_last, temp);
      mpz_clear(ai_last);
      copyref_mpz(ai_last, ai_cur);
      copyref_mpz(ai_cur, temp);
    }

    if (bi) {
      mpz_init(temp);
      mpz_mul(temp, q, bi_cur);
      mpz_sub(temp, bi_last, temp);
      mpz_clear(bi_last);
      copyref_mpz(bi_last, bi_cur);
      copyref_mpz(bi_cur, temp);
    }
  }

  mpz_clear(g);
  copyref_mpz(g, rem_last);
  mpz_clear(rem_cur);
  mpz_clear(q);

  if (ai) {
    mpz_clear(ai);
    copyref_mpz(ai, ai_cur);
    mpz_clear(ai_last);
  }
  if (bi) {
    mpz_clear(bi);
    copyref_mpz(bi, bi_cur);
    mpz_clear(bi_last);
  }
}

void mpz_gcdext(g, ai, bi, a, b)
     mpz_t g;
     mpz_t ai;
     mpz_t bi;
     const mpz_t a;
     const mpz_t b;
{
  if (mpz_cmpabs(a, b) > 0)
    mpz_gcdext_main(g, ai, bi, a, b);
  else
    mpz_gcdext_main(g, bi, ai, b, a);  
}

/**************** Output ****************/

#define PUTCH(bbb, sss, nnn, ccc) do {		\
    if ((sss) > 1) {				\
      *(bbb) = (ccc);				\
      (bbb)++;					\
      (sss)--;					\
    }						\
    (nnn)++;					\
  } while (0)

static int putnum(char** buf, size_t* size, unsigned long value,
		  unsigned int base)
{
  unsigned long s;
  unsigned int d;
  int count = 0;

  if (value == 0) {
    PUTCH(*buf, *size, count, '0');
  }
  else {
    s = value / base;
    if (s)
      count = putnum(buf, size, value / base, base);
    d = value % base;
    if (d < 10)
      PUTCH(*buf, *size, count, d + '0');
    else
      PUTCH(*buf, *size, count, d + 'A' - 10);
  }

  return count;
}

/* Supported conversions:
   %% %s %c %d %i %o %u %X %ld %li %lo %lu %lX %ZX
 */

int rs_vsnprintf(char* buf, size_t size, const char* fmt, va_list ap)
{
  int count = 0;
  int argtype, convtype;
  const char* strval;
  long longval;
  struct _mpz *mpval;
  limb_t v, d;
  size_t i;
  int j;

  while (fmt[0]) {
    if (fmt[0] != '%') {
      PUTCH(buf, size, count, fmt[0]);
      fmt++;
    }
    else if (fmt[1] == '%') {
      PUTCH(buf, size, count, '%');
      fmt += 2;
    }
    else {
      if (fmt[1] == 'l' || fmt[1] == 'Z') {
	argtype = fmt[1];
	convtype = fmt[2];
	fmt += 3;
      }
      else {
	argtype = 0;
	convtype = fmt[1];
	fmt += 2;
      }

      if (!convtype)
	break;

      if (convtype == 's') {
	/* string argument */
	strval = va_arg(ap, const char *);
	if (!strval)
	  strval = "(NULL)";
	while (*strval) {
	  PUTCH(buf, size, count, *strval);
	  strval++;
	}
      }
      else if (convtype == 'c' || convtype == 'd' || convtype == 'i'
	       || convtype == 'u' || convtype == 'x' || convtype == 'X') {
	if (argtype == 'Z') {
	  /* mpz argument -- always print in hexadecimal */
	  mpval = va_arg(ap, struct _mpz *);

	  if (mpval->sign < 0)
	    PUTCH(buf, size, count, '-');

	  v = IDX(mpval, mpval->size - 1);
	  count += putnum(&buf, &size, v, 16);

	  for (i = mpval->size - 1; i > 0; i--) {
	    v = IDX(mpval, i - 1);
	    for (j = LIMB_BITS - 4; j >= 0; j -= 4) {
	      d = ((v >> j) & 0x0f);
	      if (d < 10)
		PUTCH(buf, size, count, d + '0');
	      else
		PUTCH(buf, size, count, d + 'A' - 10);
	    }
	  }
	}
	else {
	  /* int or long argument */
	  if (argtype == 'l')
	    longval = va_arg(ap, long);
	  else
	    longval = va_arg(ap, int);

	  if (convtype == 'c') {
	    PUTCH(buf, size, count, (char) (unsigned char) longval);
	  }
	  else if (convtype == 'x' || convtype == 'X') {
	    count += putnum(&buf, &size, longval, 16);
	  }
	  else if (convtype == 'o') {
	    count += putnum(&buf, &size, longval, 8);
	  }
	  else if (convtype == 'u' || longval >= 0) {
	    count += putnum(&buf, &size, longval, 10);
	  }
	  else {
	    PUTCH(buf, size, count, '-');
	    count += putnum(&buf, &size, -longval, 10);
	  }
	}
      }
      else {
	fprintf(stderr, "*** ERROR: mpz: unsupported conversion '%%%c'",
		convtype);
	if (argtype)
	  PUTCH(buf, size, count, argtype);
	PUTCH(buf, size, count, convtype);
      }
    }
  }

  if (size != 0)
    *buf = 0;

  return count;
}

int rs_snprintf(char* buf, size_t size, const char* fmt, ...)
{
  va_list ap;
  int count;

  va_start(ap, fmt);
  count = rs_vsnprintf(buf, size, fmt, ap);
  va_end(ap);

  return count;
}

