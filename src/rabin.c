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

#include "rabbitsign.h"
#include "internal.h"

/*
 * Compute square root of x modulo p, where p === 3 (mod 4).
 *
 * (Assume that (x|p) = 1.)
 *
 * Notice that:
 *
 *  p = 4k + 3
 *
 *  x^[(p-1)/2] = x^(2k+1) = (x|p) = 1
 *
 *  x^(2k+2) = x
 *
 *  [x^(k+1)]^2 = x
 *
 *  so x^(k+1) = x^[(p+1)/4] is a square root of x.
 */
static void mpz_sqrtm_3 (mpz_t res,     /* mpz to store result */
			 const mpz_t x, /* number to get square root of */
			 const mpz_t p) /* prime modulus === 3 (mod 4) */
{
  mpz_add_ui(res, p, 1);
  mpz_fdiv_q_2exp(res, res, 2);	/* (p + 1)/4 */
  mpz_powm(res, x, res, p);
}


/*
 * Compute square root of x modulo p, where p === 5 (mod 8).
 *
 * (Assume that (x|p) = 1.)
 *
 * Notice that:
 *
 *  p = 4k + 1
 *
 *  x^[(p-1)/2] = x^(2k) = (x|p) = 1
 *
 *  x^[(k+1)/2]^2 * x^(4k-1) = x^(5k) = x^k
 *
 *  Since x^k^2 = 1, x^k = +/- 1.
 *
 *  CASE 1:
 *    If x^k = 1, x^[(k+1)/2]^2 = x, so x^[(k+1)/2] = x^[(p+3)/8] is
 *    the square root of x.
 *
 *  CASE 2:
 *    Otherwise, x^[(k+1)/2]^2 = -x; we need to find a square root of
 *    -1.
 *
 *    Since (2|p) = -1, 2^[(p-1)/2] = 2^(2k) = -1, so (2^k)^2 = -1
 *
 *    (x^[(k+1)/2] * 2^k)^2 = -x * -1 = x
 *
 *    so x^[(k+1)/2] * 2^k = x^[(p+3)/8] * 2^[(p-1)/4] is the square
 *    root of x.
 */
static void mpz_sqrtm_5 (mpz_t res,	/* mpz to store result */
			 const mpz_t x,	/* number to get square root of */
			 const mpz_t p)	/* prime modulus === 5 (mod 8) */
{
  mpz_t a, b;
  mpz_init(a);
  mpz_init(b);

  mpz_add_ui(a, p, 3);
  mpz_fdiv_q_2exp(b, a, 3);
  mpz_powm(res, x, b, p);	/* x ^ (p+3)/8 */

  /* Check if res^2 = x */
  mpz_mul(a, res, res);
  mpz_sub(b, a, x);
  mpz_mod(a, b, p);

  if (0 != mpz_sgn(a)) {
    mpz_sub_ui(a, p, 1);
    mpz_fdiv_q_2exp(b, a, 2);
    mpz_set_ui(a, 2);
    mpz_powm(a, a, b, p);	/* 2 ^ (p-1)/4 */
    mpz_mul(res, res, a);
  }

  mpz_clear(a);
  mpz_clear(b);
}


/*
 * Compute square root of x modulo p.
 *
 * This still won't work with p === 1 mod 8, but then, TI's system
 * won't work at all for 50% of apps if one of your factors is 1 mod
 * 8.  (See the discussion of f values below.)
 *
 */
static void mpz_sqrtm (mpz_t res,      /* mpz to store result */
		       const mpz_t x,  /* number to get square root of */
		       const mpz_t p)  /* prime modulus === 3, 5, or 7
					  (mod 8) */
{
  if ((mpz_get_ui(p) % 8) == 5)
    mpz_sqrtm_5(res, x, p);
  else 
    mpz_sqrtm_3(res, x, p);
}


/*
 * Compute x s.t. x === r (mod p) and x === s (mod q).
 *
 * We compute this as:
 *
 *  [(r-s) * q^-1 mod p] * q + s
 *
 */
static void mpz_crt(mpz_t res,	      /* mpz to store result */
		    const mpz_t r,    /* root modulo p */
		    const mpz_t s,    /* root modulo q */
		    const mpz_t p,    /* first modulus */
		    const mpz_t q,    /* second modulus */
		    const mpz_t qinv) /* q^(p-2) mod p */
{
  /* ((r - s) */
  mpz_sub(res, r, s);

  /* * q^-1) */
  mpz_mul(res, res, qinv);
  mpz_mod(res, res, p);

  /* * q + s */
  mpz_mul(res, res, q);
  mpz_add(res, res, s);
}

/*
 * Compute the T_f transform modulo n.
 *
 * Because only one quarter of the possible hashes can be signed with
 * a given key, we need to transform the hash.  First, we want to
 * ensure that the result is nonzero, so we shift the hash by 8 bits
 * and add a 1 to the end.  The resulting number is called m'.
 *
 * Second, we want to multiply it by a number k whose Legendre symbols
 * (k|p) and (k|q) are known, so that (km'|p) = (k|p)(m'|p) = 1 and
 * (km'|q) = (k|q)(km'|q) = 1.  Since we need both to be true
 * simultaneously, regardless of the values of (m'|p) and (m'|q), we
 * clearly need four possible values of k.
 *
 * As it happens, TI's keys all follow a precise format: they all have
 * p === 3 and q === 7 (mod 8).  As a result, we know that
 *
 *  (-1|p) = (-1|q) = -1
 *
 *  (2|p) = -1, (2|q) = 1
 *
 * So TI has defined the following transformation functions:
 *
 *  T_0(x) = -2x'
 *  T_1(x) = -x'
 *  T_2(x) = x'
 *  T_3(x) = 2x'
 *
 * where x' = 256x + 1.
 *
 * In the usual case of p === 3 and q === 7 (mod 8), then, two of the
 * possible (T_f(m)|p) will equal 1:
 *
 *  If (m'|p) = 1, then (T_0(m)|p) = (T_2(m)|p) = 1.
 *  If (m'|p) = -1, then (T_1(m)|p) = (T_3(m)|p) = 1.
 *
 * Two of the possible (T_f(m)|q) will equal 1:
 *
 *  If (m'|q) = 1, then (T_2(m)|q) = (T_3(m)|q) = 1.
 *  If (m'|q) = -1, then (T_0(m)|q) = (T_1(m)|q) = 1.
 *
 * Thus we can choose exactly one f value with
 * (T_f(m)|p) = (T_f(m)|q) = 1.
 *
 * If r === 5 (mod 8) is a prime, (-1|r) = 1, while (2|r) = -1.  Thus
 * a similar logic holds:
 *
 *  If (m'|r) = 1, then (T_1(m)|r) = (T_2(m)|r) = 1.
 *  If (m'|r) = -1, then (T_0(m)|r) = (T_3(m)|r) = 1.
 *
 * So if {p,q} === {3,5}, {5,7}, or {3,7} (mod 8), given any m, we can
 * pick an f with (T_f(m)|p) = (T_f(m)|q) = 1.
 *
 */
static void applyf(mpz_t res,	  /* mpz to store result */
		   const mpz_t m, /* MD5 hash */
		   const mpz_t n, /* public key */
		   int f)	  /* f (0, 1, 2, 3) */
{
  mpz_mul_ui(res, m, 256);
  mpz_add_ui(res, res, 1);

  switch (f) {
  case 0:
    mpz_add(res, res, res);
  case 1:
    mpz_sub(res, n, res);
    break;
  case 2:
    break;
  case 3:
    mpz_add(res, res, res);
    break;
  }
}

/*
 * Compute the Rabin signature with a given f.
 */
static void rabsigf(mpz_t res,	      /* mpz to store result */
		    const mpz_t m,    /* MD5 hash */
		    const mpz_t n,    /* public key */
		    const mpz_t p,    /* first factor */
		    const mpz_t q,    /* second factor */
		    const mpz_t qinv, /* q^(p-2) mod p */
		    int f,	      /* f (0, 1, 2, 3) */
		    int rootnum)      /* root number (0, 1, 2, 3) */
{
  mpz_t mm;
  mpz_t r,s;

  mpz_init(r);
  mpz_init(s);
  mpz_init(mm);

  applyf(mm, m, n, f);

  mpz_sqrtm(r, mm, p);
  mpz_sqrtm(s, mm, q);

  if (rootnum & 1) {
    mpz_sub(r, p, r);
  }

  if (rootnum & 2) {
    mpz_sub(s, q, s);
  }

  mpz_crt(res, r, s, p, q, qinv);

  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(mm);
}

/* 
 * Table of f values. 
 *
 * Remember that
 *
 * f = 0 corresponds to multiplying by -2
 * f = 1 corresponds to multiplying by -1
 * f = 2 corresponds to multiplying by 1
 * f = 3 corresponds to multiplying by 2
 */
static const int ftab[36] = {
  /************* (m'|p) = (m'|q) = 1 */
     /********** (m'|p) = -1, (m'|q) = 1 */
         /****** (m'|p) = 1, (m'|q) = -1 */
            /*** (m'|p) = (m'|q) = -1 */

  /* p === 3, q === 3 */
  2, 99, 99,1,  /* (-1|p) = (-1|q) = -1     ==> if both -1, multiply by -1 */

  /* p === 3, q === 5 */
  2, 1,  0, 3,  /* (-1|p) = -1, (-1|q) = 1  ==> if (m'|p) = -1, multiply by -1 */
                /* (-2|p) = 1, (-2|q) = -1  ==> if (m'|q) = -1, multiply by -2 */

  /* p === 3, q === 7 */
  2, 3,  0, 1,  /* (2|p) = -1, (2|q) = 1    ==> if (m'|p) = -1, multiply by 2 */
                /* (-2|p) = 1, (-2|q) = -1  ==> if (m'|q) = -1, multiply by -2 */

  /* p === 5, q === 3 */
  2, 0,  1, 3,

  /* p === 5, q === 5 */
  2, 99, 99,3,  /* (2|p) = (2|q) = -1       ==> if both -1, multiply by 2 */

  /* p === 5, q === 7 */
  2, 3,  1, 0,  /* (2|p) = -1, (2|q) = 1    ==> if (m'|p) = -1, multiply by 2 */
                /* (-1|p) = 1, (-1|q) = -1  ==> if (m'|q) = -1, multiply by -1 */

  /* p === 7, q === 3 */
  2, 0,  3, 1,

  /* p === 7, q === 5 */
  2, 1,  3, 0,

  /* p === 7, q === 7 */
  2, 99, 99,1   /* (-1|p) = (-1|q) = -1     ==> if both -1, multiply by -1 */
};

/*
 * Compute the Rabin signature and the useful value of f.
 */
int rs_sign_rabin(mpz_t res,	        /* mpz to store signature */
		  int* f,	        /* f value chosen */
		  const mpz_t hash,	/* MD5 hash of app */
		  int rootnum,		/* root number (0, 1, 2, 3) */
		  RSKey* key)		/* key structure */
{
  mpz_t mm;
  int mLp, mLq;
  int pm8, qm8;

  if (!mpz_sgn(key->n)) {
    rs_error(key, NULL, "unable to sign: public key missing");
    return RS_ERR_MISSING_PUBLIC_KEY;
  }

  if (!mpz_sgn(key->p) || !mpz_sgn(key->q)) {
    rs_error(key, NULL, "unable to sign: private key missing");
    return RS_ERR_MISSING_PRIVATE_KEY;
  }

  mpz_init(mm);

  /* Calculate q^-1 if necessary */

  if (!mpz_sgn(key->qinv)) {
#ifndef USE_MPZ_GCDEXT
    mpz_sub_ui(mm, key->p, 2);
    mpz_powm(key->qinv, key->q, mm, key->p);
#else
    mpz_gcdext(mm, key->qinv, NULL, key->q, key->p);
    if (mpz_cmp_ui(mm, 1)) {
      mpz_clear(mm);
      rs_error(key, NULL, "unable to sign: unsuitable key");
      return RS_ERR_UNSUITABLE_RABIN_KEY;
    }
#endif
  }

  applyf(mm, hash, key->n, 2);

  mLp = mpz_legendre(mm, key->p);
  mLq = mpz_legendre(mm, key->q);

  pm8 = mpz_get_ui(key->p) % 8;
  qm8 = mpz_get_ui(key->q) % 8;

  if (pm8 == 1 || qm8 == 1 || (pm8 % 2) == 0 || (qm8 % 2) == 0) {
    mpz_clear(mm);
    rs_error(key, NULL, "unable to sign: unsuitable key");
    return RS_ERR_UNSUITABLE_RABIN_KEY;
  }

  *f = ftab[(mLp == 1 ? 0 : 1) +
	    (mLq == 1 ? 0 : 2) +
	    (((qm8 - 3) / 2) * 4) +
	    (((pm8 - 3) / 2) * 12)];

  if (*f == 99) {
    mpz_clear(mm);
    rs_error(key, NULL, "unable to sign: unsuitable key");
    return RS_ERR_UNSUITABLE_RABIN_KEY;
  }

  rabsigf(res, hash, key->n, key->p, key->q, key->qinv, *f, rootnum);
  mpz_clear(mm);
  return RS_SUCCESS;
}

/* Check that the given Rabin signature is valid. */
int rs_validate_rabin (const mpz_t sig,  /* purported signature of app */
		       int f,		 /* f value */
		       const mpz_t hash, /* MD5 hash of app */
                       const RSKey* key) /* key structure */
{
  mpz_t a, b;
  int result;

  if (!mpz_sgn(key->n)) {
    rs_error(key, NULL, "unable to validate: public key missing");
    return RS_ERR_MISSING_PUBLIC_KEY;
  }

  if (f < 0 || f > 3)
    return RS_SIGNATURE_INCORRECT;

  mpz_init(a);
  mpz_init(b);

  mpz_mul(a, sig, sig);
  mpz_mod(a, a, key->n);

  applyf(b, hash, key->n, f);

  result = mpz_cmp(a, b);

  mpz_clear(a);
  mpz_clear(b);
  return (result ? RS_SIGNATURE_INCORRECT : RS_SUCCESS);
}
