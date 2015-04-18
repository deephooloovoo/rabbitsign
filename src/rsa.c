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

#define VALIDATION_EXPONENT 17

/*
 * Calculate the RSA signing exponent.
 *
 * The validation exponent, e, is 17 for all TI-related RSA
 * signatures.  The signing exponent, d, depends on n, and is
 * calculated so that e * d === 1 (mod (p-1)(q-1)).
 *
 * (This means that for any number x,
 *
 *  x^(e * d) = x * x^[k0 * (p-1)] === x * 1 (mod p),
 *
 * and likewise
 *
 *  x^(e * d) = x * x^[k1 * (q-1)] === x * 1 (mod q).
 *
 * Therefore (Chinese remainder theorem) x^(e * d) === x (mod n).
 *
 * Note that there is no way of calculating d without knowing the
 * factors of n; this is a key point in the security of RSA.)
 */
static int get_exponent(mpz_t res,	/* mpz to store result */
			mpz_t e,		/* validation exponent */
			const mpz_t p,  /* first factor */
			const mpz_t q)  /* second fatctor */
{
  mpz_t a, b;
  mpz_init(a);
  mpz_init(b);

  mpz_sub_ui(a, p, 1);
  mpz_sub_ui(b, q, 1);
  mpz_mul(a, a, b);

  mpz_set(b, e);

  mpz_gcdext(b, res, NULL, b, a);
  if (mpz_cmp_ui(b, 1)) {
    mpz_clear(a);
    mpz_clear(b);
    return RS_ERR_UNSUITABLE_RSA_KEY;
  }

  mpz_mod(res, res, a);

  mpz_clear(a);
  mpz_clear(b);
  return RS_SUCCESS;
}

/*
 * Compute an RSA signature.
 *
 * This is simply the hash raised to the d-th power mod n (where d is
 * defined above.)
 */
int rs_sign_rsa(mpz_t res,	   /* mpz to store signature */
		const mpz_t hash, /* MD5 hash of app */
		RSKey* key)	   /* key structure */
{
  if (!mpz_sgn(key->n)) {
    rs_error(key, NULL, "unable to sign: public key missing");
    return RS_ERR_MISSING_PUBLIC_KEY;
  }

  if (!mpz_sgn(key->d)) {
    if (!mpz_sgn(key->p) || !mpz_sgn(key->q)) {
      rs_error(key, NULL, "unable to sign: private key missing");
      return RS_ERR_MISSING_PRIVATE_KEY;
    }
    if (get_exponent(key->d, key->e, key->p, key->q)) {
      rs_error(key, NULL, "unable to sign: unsuitable key");
      return RS_ERR_UNSUITABLE_RSA_KEY;
    }
  }

  mpz_powm(res, hash, key->d, key->n);
  return RS_SUCCESS;
}

/*
 * Check that the given RSA signature is valid.
 *
 * To do this, we raise the signature to the 17th power mod n, and see
 * if it matches the hash.
 */
int rs_validate_rsa(const mpz_t sig,  /* purported signature of app */
		    const mpz_t hash, /* MD5 hash of app */
                    const RSKey* key) /* key structure */
{
  mpz_t e, m;
  int result;

  if (!mpz_sgn(key->n)) {
    rs_error(key, NULL, "unable to validate: public key missing");
    return RS_ERR_MISSING_PUBLIC_KEY;
  }

  mpz_init(e);
  mpz_init(m);

  mpz_set(e, key->e);
  mpz_powm(m, sig, e, key->n);
  result = mpz_cmp(hash, m);

  mpz_clear(e);
  mpz_clear(m);
  return (result ? RS_SIGNATURE_INCORRECT : RS_SUCCESS);
}
