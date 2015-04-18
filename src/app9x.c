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
#include <stdint.h>
#include "rabbitsign.h"
#include "internal.h"
#include "md5.h"
#include "sha256.h"

/*
 * Check/fix app/OS header and data.
 *
 * (This is something of a work in progress; a lot more
 * experimentation would be useful to determine what exactly is
 * required of app and OS headers on the 68k calculators.)
 */
static int repair_app(RSProgram* app,     /* app to repair */
		      unsigned int flags, /* flags */
		      unsigned int type)  /* field type */
{
  unsigned long length, hdrstart, hdrsize, fieldhead,
    fieldstart, fieldsize;
  unsigned char *hdr;
  int e;

  if (app->length < 6
      || app->data[0] != type
      || (app->data[1] & 0xf0) != 0) {
    rs_error(NULL, app, "no app header found");
    return RS_ERR_MISSING_HEADER;
  }

  /* Determine application length */

  length = app->length;
  rs_get_field_size(app->data, &hdrstart, &hdrsize);

  /* If requested, remove the old signature (truncate the application
     to its stated length.) */

  if (flags & RS_REMOVE_OLD_SIGNATURE) {
    if (length < hdrstart + hdrsize) {
      rs_warning(NULL, app, "provided app data too short");
    }
    else {
      if (length > hdrstart + hdrsize + 67)
	rs_warning(NULL, app, "re-signing discards %lu bytes",
		   length - hdrstart - hdrsize);
      length = hdrstart + hdrsize;
    }
  }
  else if (hdrsize && hdrstart + hdrsize != length) {
    rs_warning(NULL, app, "application length incorrect");
    rs_warning(NULL, app, "(perhaps you meant to use -r?)");
  }

  if ((e = rs_program_set_length(app, length)))
    return e;

  /* Set app size header to the correct value */

  hdrsize = length - hdrstart;
  if (rs_set_field_size(app->data, hdrsize)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "cannot set application length");
    else {
      rs_error(NULL, app, "cannot set application length");
      return RS_ERR_FIELD_TOO_SMALL;
    }
  }

  /* Check for key ID */

  hdr = app->data + hdrstart;
 // if (hdrsize > 128)
 //   hdrsize = 128;

  if (rs_find_app_field((type << 8) | 0x10, hdr, hdrsize,
			NULL, NULL, NULL)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no key ID");
    else {
      rs_error(NULL, app, "application has no key ID");
      return RS_ERR_MISSING_KEY_ID;
    }
  }

  /* Check for date stamp (note: I haven't actually tested whether
     this is required, but it always seems to be present in both 68k
     apps and OSes, and it is required for TI-83+ apps) */

  if (rs_find_app_field(0x0320, hdr, hdrsize,
			NULL, &fieldstart, &fieldsize)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no date stamp");
    else {
      rs_error(NULL, app, "application has no date stamp");
      return RS_ERR_MISSING_DATE_STAMP;
    }
  }
/*  else if (rs_find_app_field(0x0900, hdr + fieldstart, fieldsize,
			NULL, NULL, NULL)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no date stamp");
    else {
      rs_error(NULL, app, "application has no date stamp");
      return RS_ERR_MISSING_DATE_STAMP;
    }
  }
  else if (hdr[fieldstart + fieldsize] != 0x02
      || (hdr[fieldstart + fieldsize + 1] & 0xf0) != 0) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no date stamp signature");
    else {
      rs_error(NULL, app, "application has no date stamp signature");
      return RS_ERR_MISSING_DATE_STAMP;
    }
  }*/

  /* Check for program image field and fix length */

  if (rs_find_app_field((type << 8) | 0x70, hdr, hdrsize,
			&fieldhead, &fieldstart, &fieldsize)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no program image field");
    else {
      rs_error(NULL, app, "application has no program image field");
      return RS_ERR_MISSING_PROGRAM_IMAGE;
    }
  }
  else {
    if ((fieldstart + hdrstart) % 2) {
      /* The OS appears to align apps so the start of the app header
	 is at an even address; if the application code itself is at
	 an odd address, bad stuff will happen. */
      if (flags & RS_IGNORE_ALL_WARNINGS)
	rs_warning(NULL, app, "application header is not a multiple of 2 bytes");
      else {
	rs_error(NULL, app, "application header is not a multiple of 2 bytes");
	return RS_ERR_MISALIGNED_PROGRAM_IMAGE;
      }
    }

    if (fieldsize && fieldstart + fieldsize != length - hdrstart)
      rs_warning(NULL, app, "program image length incorrect");

    if (rs_set_field_size(hdr + fieldhead, length - hdrstart - fieldstart)) {
      rs_error(NULL, app, "cannot set program image length");
      return RS_ERR_FIELD_TOO_SMALL;
    }
  }

  return RS_SUCCESS;
}

/*
 * Check/fix Flash app header and data.
 */
int rs_repair_ti9x_app(RSProgram* app,     /* app to repair */
		       unsigned int flags) /* flags */
{
  return repair_app(app, flags, 0x81);
}

/*
 * Check/fix OS header and data.
 */
int rs_repair_ti9x_os(RSProgram* app,     /* app to repair */
		      unsigned int flags) /* flags */
{
  return repair_app(app, flags, 0x80);
}

/*
 * Compute signature for a 68k app/OS.
 *
 * The app header should be checked and/or repaired by
 * rs_repair_ti9x_app() prior to calling this function.
 */
int rs_sign_ti9x_app(RSProgram* app, /* app to sign */
		     RSKey* key)     /* signing key */
{
  md5_uint32 md5hash[4];
  uint32_t sha256hash[8];
  struct sha256_ctx sha256ctx;
  mpz_t hashv, sigv;
  unsigned char sigdata[512];
  size_t siglength;
  int e;
  mpz_init(hashv);
  mpz_init(sigv);
  if (app->keytype == RS_KEY_SHA256) {
    sha256_init_ctx(&sha256ctx);
    sha256_process_bytes((char*) app->data,app->length,&sha256ctx);
    sha256_finish_ctx(&sha256ctx,sha256hash);
    
    mpz_import(hashv, 32, -1, 1, 0, 0, sha256hash);
  } else {
    md5_buffer((char*) app->data, app->length, &md5hash);
    mpz_import(hashv, 16, -1, 1, 0, 0, &md5hash);
  }




  rs_message(2, NULL, app, "hash = %ZX", hashv);

  if ((e = rs_sign_rsa(sigv, hashv, key))) {
    mpz_clear(hashv);
    mpz_clear(sigv);
    return e;
  }

  rs_message(2, NULL, app, "sig = %ZX", sigv);

  sigdata[0] = 0x02;
  //sigdata[1] = 0x2d;
  sigdata[1]=0x3e;

  mpz_export(sigdata + 4, &siglength, -1, 1, 0, 0, sigv);
  sigdata[2]=(siglength&0xff00)>>8;
  sigdata[3] = siglength & 0xff;
  siglength += 4;

  return rs_program_append_data(app, sigdata, siglength);
}

/*
 * Validate app/OS signature.
 */
int rs_validate_ti9x_app(const RSProgram* app, /* app to validate */
			 const RSKey* key)     /* signing key */
{
  unsigned long length, hdrstart, hdrsize, fieldstart, fieldsize;
  const unsigned char *hdr, *sig;
  md5_uint32 md5hash[4];
  uint32_t sha256hash[8];
  struct sha256_ctx sha256ctx;
  mpz_t hashv, sigv;
  int e, e2 = RS_SUCCESS;

  if (app->length < 6) {
    rs_error(NULL, app, "no app header found");
    return RS_ERR_MISSING_HEADER;
  }

  rs_get_field_size(app->data, &hdrstart, &hdrsize);
  length = hdrstart + hdrsize;
  hdr = app->data + hdrstart;
  //if (hdrsize > 128)
  //  hdrsize = 128;

  if (length + 4 > app->length || length + 367 < app->length) {
    rs_error(NULL, app, "incorrect application length");
    return RS_ERR_INCORRECT_PROGRAM_SIZE;
  }

  if (rs_find_app_field((app->data[0] << 8) | 0x70, hdr, hdrsize,
			NULL, &fieldstart, &fieldsize)) {
    rs_warning(NULL, app, "application has no program image field");
    e2 = RS_ERR_MISSING_PROGRAM_IMAGE;
  }
  else if ((fieldstart + hdrstart) % 2) {
    rs_warning(NULL, app, "application header is not a multiple of 2 bytes");
    e2 = RS_ERR_MISALIGNED_PROGRAM_IMAGE;
  }

  //md5_buffer((char*) app->data, length, &md5hash);
  //sha256_process_bytes((char*) app->data,app->length,&sha256hash);
  mpz_init(hashv);
  mpz_init(sigv);
  if (app->keytype == RS_KEY_SHA256) {
    sha256_init_ctx(&sha256ctx);
    sha256_process_bytes(app->data,length,&sha256ctx);
    sha256_finish_ctx(&sha256ctx,sha256hash);
    
    mpz_import(hashv, 32, -1, 1, 0, 0, sha256hash);
  } else {
    md5_buffer((char*) app->data, app->length, &md5hash);
    mpz_import(hashv, 16, -1, 1, 0, 0, &md5hash);
  }
  sig = app->data + length;
  if (sig[0] != 0x02 || 
      (((sig[1] & 0xf0) != 0x00 ) && ((sig[1]&0xf0)!=0x30))) {
      rs_error(NULL, app, "application does not have an RSA signature");
      return RS_ERR_MISSING_RSA_SIGNATURE;
  }
  rs_get_field_size(sig, &fieldstart, &fieldsize);

//  mpz_import(hashv, 16, -1, 1, 0, 0, sha256hash.H);
  rs_message(2, NULL, app, "hash = %ZX", hashv);

  mpz_import(sigv, fieldsize, -1, 1, 0, 0, sig + fieldstart);
  rs_message(2, NULL, app, "sig = %ZX", sigv);

  e = rs_validate_rsa(sigv, hashv, key);
  if (e == RS_SIGNATURE_INCORRECT)
    rs_message(0, NULL, app, "application signature incorrect");

  mpz_clear(sigv);
  mpz_clear(hashv);
  return (e ? e : e2);
}

