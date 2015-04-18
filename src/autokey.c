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

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif

#include "rabbitsign.h"
#include "internal.h"
#include "autokeys.h"

/*
 * Get key ID for the given program.
 */
unsigned long rs_program_get_key_id(const RSProgram* prgm)
{
  const unsigned char* hdr;
  unsigned long hdrstart, hdrsize;

  if (prgm->header_length > 0) {
    hdr = prgm->header;
    hdrsize = prgm->header_length;
  }
  else if (prgm->length > 0) {
    hdr = prgm->data;
    hdrsize = prgm->length;
    if (hdrsize > 128)
      hdrsize = 128;
  }
  else
    return 0;

  rs_get_field_size(hdr, &hdrstart, NULL);
  hdrsize -= hdrstart;

  if (hdr[0] == 0x81)
    return rs_get_numeric_field(0x8110, hdr + hdrstart, hdrsize);
  else
    return rs_get_numeric_field(0x8010, hdr + hdrstart, hdrsize);
}

/*
 * Try to load key from a file.
 */
static int try_key_file(RSKey* key, /* key structure to store result */
			const char* a, /* first path element */
			const char* b, /* second path element */
			const char* c) /* third path element */
{
  char* s;
  FILE* f;
  int e;

  s = rs_malloc(strlen(a) + strlen(b) + strlen(c) + 1);
  if (!s)
    return RS_ERR_OUT_OF_MEMORY;
  strcpy(s, a);
  strcat(s, b);
  strcat(s, c);

  f = fopen(s, "rt");
  if (!f) {
    rs_free(s);
    return RS_ERR_KEY_NOT_FOUND;
  }

  if ((e = rs_read_key_file(key, f, s, 1))) {
    fclose(f);
    rs_free(s);
    return e;
  }

  fclose(f);
  rs_free(s);
  return RS_SUCCESS;
}

/*
 * Try to locate a given key file.
 */
static int find_key_file(RSKey* key,           /* key structure to
						  store result */
			 const char* filename) /* file name to search
						  for */
{
  const char* p;
  int e;

  e = try_key_file(key, "", "", filename);
  if (e != RS_ERR_KEY_NOT_FOUND)
    return e;

  if ((p = getenv("RABBITSIGN_KEY_DIR"))) {
#if defined(__MSDOS__) || defined(__WIN32__)
    e = try_key_file(key, p, "\\", filename);
#else
    e = try_key_file(key, p, "/", filename);
#endif
    if (e != RS_ERR_KEY_NOT_FOUND)
      return e;
  }

#if defined(__MSDOS__) || defined(__WIN32__)
  if ((p = getenv("TI83PLUSDIR"))) {
    e = try_key_file(key, p, "\\Utils\\", filename);
    if (e != RS_ERR_KEY_NOT_FOUND)
      return e;
  }
#endif

#ifdef SHARE_DIR
  e = try_key_file(key, SHARE_DIR, "", filename);
  if (e != RS_ERR_KEY_NOT_FOUND)
    return e;
#endif

  return RS_ERR_KEY_NOT_FOUND;
}

/*
 * Find key file for the given ID.
 */
int rs_key_find_for_id(RSKey* key,	    /* key structure to store
					       result */
		       unsigned long keyid, /* key ID to search for */
		       int publiconly)	    /* 1 = search for public
					       key only */
{
  static const char* fmts[] = { "%02lx.%s", "%02lX.%s",
				"%04lx.%s", "%04lX.%s", NULL };
  char buf[16];
  int i, e;

  mpz_set_ui(key->p, 0);
  mpz_set_ui(key->q, 0);
  mpz_set_ui(key->e, 17);
  mpz_set_ui(key->qinv, 0);
  mpz_set_ui(key->d, 0);

  if (keyid > 0xFF)
    sprintf(buf, "%04lX", keyid);
  else
    sprintf(buf, "%02lX", keyid);

  for (i = 0; known_priv_keys[i].n; i++) {
    if (keyid == known_priv_keys[i].id) {
      if ((e = rs_parse_key_value(key->n, known_priv_keys[i].n)))
	return e;

      if (known_priv_keys[i].p
	  && (e = rs_parse_key_value(key->p, known_priv_keys[i].p)))
	return e;
      if (known_priv_keys[i].q
	  && (e = rs_parse_key_value(key->q, known_priv_keys[i].q)))
	return e;
      if (known_priv_keys[i].d
	  && (e = rs_parse_key_value(key->d, known_priv_keys[i].d)))
	return e;

      rs_message(2, key, NULL, "Loaded builtin private key %s:", buf);
      rs_message(2, key, NULL, " n = %ZX", key->n);
      if (mpz_sgn(key->p))
	rs_message(2, key, NULL, " p = %ZX", key->p);
      if (mpz_sgn(key->q))
	rs_message(2, key, NULL, " q = %ZX", key->q);
      if (mpz_sgn(key->d))
	rs_message(2, key, NULL, " d = %ZX", key->d);

      key->id = keyid;
      return 0;
    }
  }

  if (publiconly) {
    for (i = 0; known_pub_keys[i].n; i++) {
      if (keyid == known_pub_keys[i].id) {
	if ((e = rs_parse_key_value(key->n, known_pub_keys[i].n)))
	  return e;

	rs_message(2, key, NULL, "Loaded builtin public key %s:", buf);
	rs_message(2, key, NULL, " n = %ZX", key->n);

	key->id = keyid;
	return 0;
      }
    }
  }

  for (i = 0; fmts[i]; i++) {
    sprintf(buf, fmts[i], keyid, "key");
    e = find_key_file(key, buf);
    if (e != RS_ERR_KEY_NOT_FOUND) {
      if (e == 0 && !key->id)
	key->id = keyid;
      return e;
    }
  }

  if (publiconly) {
    for (i = 0; fmts[i]; i++) {
      sprintf(buf, fmts[i], keyid, "pub");
      e = find_key_file(key, buf);
      if (e != RS_ERR_KEY_NOT_FOUND) {
	if (e == 0 && !key->id)
	  key->id = keyid;
	return e;
      }
    }
  }

  rs_error(NULL, NULL, "cannot find key file %s", buf);
  return RS_ERR_KEY_NOT_FOUND;
}
