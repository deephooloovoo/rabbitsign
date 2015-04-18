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

#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif

#include "rabbitsign.h"
#include "internal.h"

/*
 * Create a new key.
 */
RSKey* rs_key_new()
{
  RSKey* key = rs_malloc(sizeof(RSKey));

  if (!key)
    return NULL;

  key->filename = NULL;
  key->id = 0;
  mpz_init(key->n);
  mpz_init(key->p);
  mpz_init(key->q);
  mpz_init(key->e);
  mpz_init(key->qinv);
  mpz_init(key->d);

  return key;
}

/*
 * Free a key.
 */
void rs_key_free(RSKey* key)
{
  if (!key)
    return;

  rs_free(key->filename);
  mpz_clear(key->n);
  mpz_clear(key->p);
  mpz_clear(key->q);
  mpz_clear(key->e);
  mpz_clear(key->qinv);
  mpz_clear(key->d);
  rs_free(key);
}

/*
 * Parse a number written in TI's hexadecimal key format.
 */
static int parse_value(mpz_t dest,	/* mpz to store result */
		       const char* str) /* string to parse */
{
  unsigned int count, b, i;
  int n=strlen(str);
  unsigned char buf[1024];
  if (  sscanf(str, "%2X%n", &count, &n)>=1 && n == 2
      && (count * 2 + 3) >= strlen(str)) {

    for (i = 0; i < count; i++) {
      if (1 > sscanf(str + 2 + 2 * i, "%2X%n", &b, &n) || n != 2)
        return 1;
      buf[i] = b;
    }

    mpz_import(dest, i, -1, 1, 0, 0, buf);
    return 0;
  } else if ( sscanf(str, "%4X%n", &count, &n)>=1 && n == 4
      && (count * 2 + 5	) >= strlen(str)) {

    for (i = 0; i < count; i++) {
      if (1 > sscanf(str + 4 + 2 * i, "%2X%n", &b, &n) || n != 2)
        return 1;
      buf[i] = b;
    }
    mpz_import(dest, i, -1, 1, 0, 0, buf);
    return 0;
  } else {
    return 1;
  }
}

/*
 * Read key from a file.
 *
 * Two formats of key file are supported:
 *
 * "Rabin" style (the type used by the TI-83 Plus SDK) consists of
 * three lines: the public key (n) followed by its two factors (p and
 * q.)
 *
 * "RSA" style (the type used by the TI-89/92 Plus SDK) also consists
 * of three lines: the key ID, the public key (n), and the signing
 * exponent (d).
 *
 * In either case, if we are only interested in validating signatures,
 * the private key may be omitted.
 *
 * Note that "Rabin" style key files can be used to generate RSA
 * signatures, but not vice versa.
 */
int rs_read_key_file(RSKey* key,        /* key structure */
		     FILE* f,	        /* file to read */
		     const char* fname, /* file name */
		     int verify)	/* 1 = check key validity */
{
  char buf[1024];
  mpz_t tmp;
  int fgs;

  rs_free(key->filename);
  key->filename = rs_strdup(fname);
  if (fname && !key->filename)
    return RS_ERR_OUT_OF_MEMORY;

  if (!fgets(buf, sizeof(buf), f)) {
    rs_error(key, NULL, "invalid key file syntax");
    return RS_ERR_KEY_SYNTAX;
  }

  if (strlen(buf) < 11) {
    if (1 > sscanf(buf, "%lX", &key->id)) {
      rs_error(key, NULL, "invalid key file syntax");
      return RS_ERR_KEY_SYNTAX;
    }

    if (!fgets(buf, sizeof(buf), f)
	|| parse_value(key->n, buf)) {
      rs_error(key, NULL, "invalid key file syntax");
      return RS_ERR_KEY_SYNTAX;
    }

    if (!fgets(buf, sizeof(buf), f)
	|| parse_value(key->d, buf))
      mpz_set_ui(key->d, 0);

    else if (verify) {
      /* We can't truly verify the key without factoring n (which is
	 possible, given d, but would take a bit of work.)  Instead,
	 test the key by performing a single RSA encryption and
	 decryption. */
      mpz_init(tmp);
      mpz_set_ui(tmp, 17);
      mpz_powm(tmp, tmp, key->e, key->n);
      mpz_powm(tmp, tmp, key->d, key->n);
      if (mpz_cmp_ui(tmp, 17)) {
	mpz_clear(tmp);
	rs_error(key, NULL, "private key incorrect (de != 1 mod phi(n))");
	return RS_ERR_INVALID_KEY;
      }
      mpz_clear(tmp);
    }

    mpz_set_ui(key->p, 0);
    mpz_set_ui(key->q, 0);
    mpz_set_ui(key->qinv, 0);
  }
  else {

    if (parse_value(key->n, buf)) {
      rs_error(key, NULL, "invalid key file");
      return RS_ERR_KEY_SYNTAX;
    }
    fgs=fgets(buf, sizeof(buf), f);
    if (fgs && strlen(buf)<11) {
      parse_value(key->e, buf);
      fgs=fgets(buf, sizeof(buf), f);
    } else {
      mpz_set_ui(key->e, 17);
    }
    if (!fgs || parse_value(key->p, buf)
	|| !fgets(buf, sizeof(buf), f)
	|| parse_value(key->q, buf)) {
      mpz_set_ui(key->p, 0);
      mpz_set_ui(key->q, 0);
    }
    else if (verify) {
      /* Verify that p * q = n (of course, that doesn't guarantee that
	 these are the only factors of n.) */
      mpz_init(tmp);
      mpz_mul(tmp, key->p, key->q);
      if (mpz_cmp(tmp, key->n)) {
	mpz_clear(tmp);
	rs_error(key, NULL, "private key incorrect (pq != n)");
	return RS_ERR_INVALID_KEY;
      }
      mpz_clear(tmp);
    }

    mpz_set_ui(key->qinv, 0);
    mpz_set_ui(key->d, 0);
    key->id = 0;
  }

  if (mpz_sgn(key->p) && mpz_sgn(key->q)) {
    rs_message(2, key, NULL, "Loaded Rabin/RSA private key:");
    rs_message(2, key, NULL, " n = %ZX", key->n);
    rs_message(2, key, NULL, " p = %ZX", key->p);
    rs_message(2, key, NULL, " q = %ZX", key->q);
  }
  else if (mpz_sgn(key->d)) {
    rs_message(2, key, NULL, "Loaded RSA private key:");
    rs_message(2, key, NULL, " n = %ZX", key->n);
    rs_message(2, key, NULL, " d = %ZX", key->d);
  }
  else {
    rs_message(2, key, NULL, "Loaded public key:");
    rs_message(2, key, NULL, " n = %ZX", key->n);
  }
  rs_message(2, key, NULL, " e = %ZX", key->e);
  return RS_SUCCESS;
}

/*
 * Parse a number written in TI's hexadecimal key format.
 */
int rs_parse_key_value(mpz_t dest,	/* mpz to store result */
		       const char* str) /* string to parse */
{
  if (parse_value(dest, str)) {
    rs_error(NULL, NULL, "invalid key value syntax");
    return RS_ERR_KEY_SYNTAX;
  }
  else {
    return RS_SUCCESS;
  }
}
