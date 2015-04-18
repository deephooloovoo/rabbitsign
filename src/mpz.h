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

#ifndef __RABBITSIGN_MPZ_H__
#define __RABBITSIGN_MPZ_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (SIZEOF_INT != 0) && (SIZEOF_LONG >= 2 * SIZEOF_INT)
typedef unsigned int limb_t;
typedef unsigned long double_limb_t;
typedef signed long signed_double_limb_t;
#else
# if (SIZEOF_SHORT != 0) && (SIZEOF_INT >= 2 * SIZEOF_SHORT)
typedef unsigned short limb_t;
typedef unsigned int double_limb_t;
typedef signed int signed_double_limb_t;
# else
typedef unsigned short limb_t;
typedef unsigned long double_limb_t;
typedef signed long signed_double_limb_t;
# endif
#endif

#define LIMB_BITS (sizeof(limb_t)*8)
#define LIMB_BYTES (sizeof(limb_t))
#define LIMB_MASK ((((double_limb_t) 1) << LIMB_BITS) - 1)

struct _mpz {
  size_t size;
  size_t size_alloc;
  limb_t* m;
  int sign;
};

typedef struct _mpz mpz_t[1];

#undef __P
#ifdef PROTOTYPES
# define __P(x) x
#else
# define __P(x) ()
#endif

void mpz_init __P((mpz_t x));
void mpz_clear __P((mpz_t x));

/* Set */
void mpz_set __P((mpz_t dest, const mpz_t src));
void mpz_set_ui __P((mpz_t dest, unsigned int a));
unsigned int mpz_get_ui __P((const mpz_t a));

/* Import/export: assume order=-1, size=1, endian=0, nails=0 */
void mpz_import __P((mpz_t dest, size_t count, int order, int size,
		     int endian, size_t nails, const void* op));
void mpz_export __P((void* dest, size_t* count, int order, int size,
		     int endian, size_t nails, const mpz_t op));

/* Check sign */
int mpz_sgn __P((const mpz_t a));

/* Compare */
int mpz_cmp __P((const mpz_t a, const mpz_t b));
int mpz_cmp_ui __P((const mpz_t a, unsigned int b));

/* Add */
void mpz_add __P((mpz_t dest, const mpz_t a, const mpz_t b));
void mpz_add_ui __P((mpz_t dest, const mpz_t a, unsigned int b));

/* Subtract */
void mpz_sub __P((mpz_t dest, const mpz_t a, const mpz_t b));
void mpz_sub_ui __P((mpz_t dest, const mpz_t a, unsigned int b));

/* Multiply */
void mpz_mul __P((mpz_t dest, const mpz_t a, const mpz_t b));
void mpz_mul_ui __P((mpz_t dest, const mpz_t a, unsigned int b));

/* Divide: requires b <= LIMB_BITS */
void mpz_fdiv_q_2exp __P((mpz_t dest, const mpz_t a, unsigned int b));

/* Modulus */
void mpz_mod __P((mpz_t dest, const mpz_t a, const mpz_t mod));

/* Modular exponent */
void mpz_powm __P((mpz_t dest, const mpz_t base, const mpz_t exp,
		   const mpz_t mod));

/* Legendre symbol */
int mpz_legendre __P((const mpz_t a, const mpz_t p));

/* Extended GCD */
void mpz_gcdext __P((mpz_t g, mpz_t ai, mpz_t bi,
		     const mpz_t a, const mpz_t b));

/* Output */
int rs_snprintf __P((char* buf, size_t size, const char* fmt, ...));

#ifdef va_start
int rs_vsnprintf __P((char* buf, size_t size, const char* fmt, va_list ap));
#endif

#ifdef __cplusplus
}
#endif

#endif
