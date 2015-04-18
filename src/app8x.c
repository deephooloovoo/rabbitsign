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
#include "md5.h"

/*
 * Check/fix Flash app header and data.
 *
 * This function checks various parts of the application header which,
 * if incorrect, are known to cause applications to be rejected by the
 * calculator.  Depending on the flags, this function will also fix
 * incorrect header fields.
 *
 * Note that this function can also add padding to the end of the app.
 * The entire signature must be stored on one page, so if there is not
 * enough room on the final page of the app, an extra page needs to be
 * added to hold the signature.
 *
 * In addition, some versions of the boot code have a bug which
 * results in incorrect MD5 hashes for applications that are 55 bytes
 * long mod 64; this function will add an extra padding byte to avoid
 * that case.
 */
int rs_repair_ti8x_app(RSProgram* app,	   /* app to repair */
		       unsigned int flags) /* flags */
{
  unsigned long length, hdrstart, hdrsize, fieldstart, fieldsize, i;
  unsigned char* hdr;
  unsigned char dummy = 0;
  int e, pagecount, addedpage = 0;

  /* Various parts of the OS, as well as other software on the
     calculator and PC, expect that every application begins with the
     bytes 80 0F -- a "long" field.  Some things may work for apps
     with an 80 0E (or even 80 0D) field, but not everything.  Please
     stick with 80 0F. */

  if (app->length < 6
      || ( app->data[0] != 0x80 && app->data[0] != 0x81 )
      || app->data[1] != 0x0f) {
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
      if (length > hdrstart + hdrsize + 96)
	rs_warning(NULL, app, "re-signing discards %lu bytes",
		   length - hdrstart - hdrsize);
      length = hdrstart + hdrsize;
    }
  }
  else if (hdrsize && hdrstart + hdrsize != length) {
    rs_warning(NULL, app, "application length incorrect");
    rs_warning(NULL, app, "(perhaps you meant to use -r?)");
  }

  /* If necessary, add an extra page to ensure that the signature
     doesn't span a page boundary. */

  if (((length + 69 + 0x3fff) >> 14) != ((length + 0x3fff) >> 14)) {
    if (flags & (RS_ZEALOUSLY_PAD_APP | RS_IGNORE_ALL_WARNINGS)) {
      rs_warning(NULL, app, "adding an extra page to hold app signature");
      length = ((length + 0x4000) & ~0x3fff) + 1;
      addedpage = 1;
    }
    else {
      rs_error(NULL, app, "application ends too close to a page boundary");
      return RS_ERR_FINAL_PAGE_TOO_LONG;
    }
  }

  if ((e = rs_program_set_length(app, length)))
    return e;

  /* If the length is 55 mod 64, add an extra byte.  (Note that, with
     512-bit keys, this can never cause a page overflow.)  We use zero
     for the padding value, rather than FF, so that our output matches
     that of other tools. */

  if ((length % 64) == 55) {
    length++;
    rs_message(2, NULL, app, "adding an extra byte due to boot code bugs");
    if ((e = rs_program_append_data(app, &dummy, 1)))
      return e;
  }

  /* Set app size header to the correct value */

  hdrsize = length - hdrstart;
  if (rs_set_field_size(app->data, hdrsize)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application length header too small");
    else {
      rs_error(NULL, app, "application length header too small");
      return RS_ERR_FIELD_TOO_SMALL;
    }
  }

  /* Check/fix page count.  This field is required to be present and
     contain the correct number of pages.  It must be one byte long
     (some parts of the OS don't even check the length and assume it
     is one byte long.) */

  hdr = app->data + hdrstart;
  if (hdrsize > 128)
    hdrsize = 128;

  if (rs_find_app_field(0x8080, hdr, hdrsize,
			NULL, &fieldstart, &fieldsize)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no page count field");
    else {
      rs_error(NULL, app, "application has no page count field");
      return RS_ERR_MISSING_PAGE_COUNT;
    }
  }
  else if (fieldsize != 1) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has an invalid page count field");
    else {   
      rs_error(NULL, app, "application has an invalid page count field");
      return RS_ERR_INCORRECT_PAGE_COUNT;
    }
  }
  else {
    pagecount = ((length + 0x3fff) >> 14);

    if (flags & RS_FIX_PAGE_COUNT) {
      hdr[fieldstart] = pagecount;
    }
    else if (addedpage && hdr[fieldstart] == pagecount - 1) {
      hdr[fieldstart] = pagecount;
    }
    else if (hdr[fieldstart] != pagecount) {
      if (flags & RS_IGNORE_ALL_WARNINGS) {
	rs_warning(NULL, app,
		   "application has an incorrect page count (actual: %lu)",
		   ((length + 0x3fff) >> 14));
	hdr[fieldstart] = pagecount;
      }
      else {      
	rs_error(NULL, app,
		 "application has an incorrect page count (actual: %lu)",
		 ((length + 0x3fff) >> 14));
	return RS_ERR_INCORRECT_PAGE_COUNT;
      }
    }
  }

  /* Check for key ID.  This field is required to be present; it
     determines which public key is used for validation.  (The
     contents of this field are usually thought of as a big-endian
     integer, but to be more precise, they're really treated as a
     binary string.) */

  if (rs_find_app_field(0x8010, hdr, hdrsize, NULL, NULL, NULL)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no key ID");
    else {
      rs_error(NULL, app, "application has no key ID");
      return RS_ERR_MISSING_KEY_ID;
    }
  }

  /* Check for date stamp.  This seems to be required -- the OS will
     use it to update its last-known date stamp if necessary -- and
     should consist of an 032x field containing an 090x field,
     followed by an 020x field containing the date stamp signature.
     (The contents of the latter only matter if the date stamp is
     "new.") */

  if (rs_find_app_field(0x0320, hdr, hdrsize,
			NULL, &fieldstart, &fieldsize)) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, app, "application has no date stamp");
    else {
      rs_error(NULL, app, "application has no date stamp");
      return RS_ERR_MISSING_DATE_STAMP;
    }
  }
  else if (rs_find_app_field(0x0900, hdr + fieldstart, fieldsize,
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
  }

  /* Check for program image field.  This field indicates the end of
     the header and the start of application code.  Note, however,
     that the OS handles this field in an exceedingly broken way.  To
     be safe, this must always be the last field of the header, and
     should always be written as 80 7F followed by four length bytes.
     The length bytes may be anything you like -- they're ignored. */

  if (rs_find_app_field(0x8070, hdr, hdrsize,
			NULL, NULL, NULL)) {
    if (rs_find_app_field(0x8170, hdr, hdrsize+0x40,
		      NULL, NULL, NULL)) {
      if (flags & RS_IGNORE_ALL_WARNINGS)
        rs_warning(NULL, app, "application has no program image field");
      else {
        rs_error(NULL, app, "application has no program image field");
        return RS_ERR_MISSING_PROGRAM_IMAGE;
      }
    }
  }

  /* Check for invalid pages (those beginning with FF.)  An OS bug
     means that such pages will end up being erased completely if
     defragmenting requires the application to be moved in Flash. */

  e = RS_SUCCESS;

  for (i = 0; i < app->length; i += 0x4000) {
    if (app->data[i] == 0xff) {
      if (flags & RS_IGNORE_ALL_WARNINGS)
	rs_warning(NULL, app, "page %ld begins with FFh", (i >> 14));
      else {
	rs_error(NULL, app, "page %ld begins with FFh", (i >> 14));
	e = RS_ERR_INVALID_PROGRAM_DATA;
      }
    }
  }

  return e;
}

/*
 * Compute signature for a Flash app.
 *
 * The app header should be checked and/or repaired by
 * rs_repair_ti8x_app() prior to calling this function.
 *
 * There are four equally valid Rabin signatures for any application;
 * rootnum determines which of the four should be used.
 */
int rs_sign_ti8x_app(RSProgram* app, /* app to sign */
		     RSKey* key,     /* signing key */
		     int rootnum)    /* signature number */
{
  md5_uint32 hash[4];
  mpz_t hashv, sigv;
  int f;
  unsigned int lastpagelength;
  unsigned char sigdata[512];
  size_t siglength;
  int e;

  /* Check if app length is risky */

  if ((app->length % 64) == 55) {
    rs_warning(NULL, app, "application has length 55 mod 64");
    rs_warning(NULL, app, "(this will fail to validate on TI-83+ BE)");
  }

  /* Compute signature */

  md5_buffer((char*) app->data, app->length, hash);

  mpz_init(hashv);
  mpz_init(sigv);

  mpz_import(hashv, 16, -1, 1, 0, 0, hash);
  rs_message(2, NULL, app, "hash = %ZX", hashv);

  if ((e = rs_sign_rabin(sigv, &f, hashv, rootnum, key))) {
    mpz_clear(hashv);
    mpz_clear(sigv);
    return e;
  }

  rs_message(2, NULL, app, "sig = %ZX", sigv);
  rs_message(2, NULL, app, "f = %d", f);

  /* Write the square root value as an 022D field... */

  sigdata[0] = 0x02;
  //sigdata[1] = 0x2d;
  sigdata[1]=0x3e;
  mpz_export(sigdata + 4, &siglength, -1, 1, 0, 0, sigv);
  sigdata[2]=(siglength&0xff00)>>8;
  sigdata[3] = siglength & 0xff;
  siglength += 4;

  mpz_clear(hashv);
  mpz_clear(sigv);

  /* ...and append the f value as a big integer */

  if (f == 0) {
    sigdata[siglength++] = 0;
  }
  else {
    sigdata[siglength++] = 1;
    sigdata[siglength++] = f;
  }

  /* Add padding, but not too much (it seems to make some link
     programs happier) */

 /* lastpagelength = app->length & 0x3fff;

  while (siglength < 96 && (lastpagelength + siglength) < 0x3fff)
    sigdata[siglength++] = 0xff;*/

  return rs_program_append_data(app, sigdata, siglength);
}

/*
 * Validate a Flash app signature.
 */
int rs_validate_ti8x_app(const RSProgram* app, /* app to validate */
			 const RSKey* key)     /* signing key */
{
  unsigned long length, hdrstart, hdrsize, fieldstart, fieldsize, i;
  const unsigned char *hdr, *sig;
  md5_uint32 hash[4];
  mpz_t hashv, sigv;
  int f, e, e2 = RS_SUCCESS;

  if (app->length < 6) {
    rs_error(NULL, app, "no app header found");
    return RS_ERR_MISSING_HEADER;
  }

  rs_get_field_size(app->data, &hdrstart, &hdrsize);
  length = hdrstart + hdrsize;
  hdr = app->data + hdrstart;
  if (hdrsize > 128)
    hdrsize = 128;

  if (((length + 0x3fff) >> 14) != ((app->length + 0x3fff) >> 14)
      || length + 4 > app->length || length + 96 < app->length) {
    rs_error(NULL, app, "incorrect application length");
    //return RS_ERR_INCORRECT_PROGRAM_SIZE;
  }

  if (rs_find_app_field(0x8070, hdr, hdrsize,
			NULL, NULL, NULL)) {
    if (rs_find_app_field(0x8170, hdr, hdrsize, NULL,NULL,NULL)) {
      rs_warning(NULL, app, "application has no program image field");
      e2 = RS_ERR_MISSING_PROGRAM_IMAGE;
    }
  }

  if (rs_find_app_field(0x8080, hdr, hdrsize,
			NULL, &fieldstart, &fieldsize)) {
    rs_warning(NULL, app, "application has no no page count field");
    e2 = RS_ERR_MISSING_PAGE_COUNT;
  }
  else if (fieldsize != 1) {
    rs_warning(NULL, app, "application has an invalid page count field");
    e2 = RS_ERR_INCORRECT_PAGE_COUNT;
  }
  else if (hdr[fieldstart] != ((length + 0x3fff) >> 14)) {
    rs_warning(NULL, app, "application has an incorrect page count field");
    e2 = RS_ERR_INCORRECT_PAGE_COUNT;
  }

  if ((length % 64) == 55) {
    rs_warning(NULL, app, "application has length 55 mod 64");
    rs_warning(NULL, app, "(this will fail to validate on TI-83+ BE)");
    e2 = RS_ERR_INVALID_PROGRAM_SIZE;
  }

  for (i = 0; i < app->length; i += 0x4000) {
    if (app->data[i] == 0xff) {
      rs_warning(NULL, app, "page %ld begins with FFh", (i >> 14));
      e2 = RS_ERR_INVALID_PROGRAM_DATA;
    }
  }

  md5_buffer((char*) app->data, length, &hash);

  sig = app->data + length;
  if (sig[0] != 0x02 || (sig[1] != 0x2d && (sig[0]&0xf0) !=0x30)) {
    rs_error(NULL, app, "application does not have a Rabin signature");
    return RS_ERR_MISSING_RABIN_SIGNATURE;
  }
  rs_get_field_size(sig, &fieldstart, &fieldsize);

  mpz_init(sigv);
  mpz_init(hashv);

  mpz_import(hashv, 16, -1, 1, 0, 0, hash);
  rs_message(2, NULL, app, "hash = %ZX", hashv);

  mpz_import(sigv, fieldsize, -1, 1, 0, 0, sig + fieldstart);
  rs_message(2, NULL, app, "sig = %ZX", sigv);

  if (sig[fieldstart + fieldsize] == 0)
    f = 0;
  else
    f = sig[fieldstart + fieldsize + 1];
  rs_message(2, NULL, app, "f = %d", f);

  e = rs_validate_rabin(sigv, f, hashv, key);
  if (e == RS_SIGNATURE_INCORRECT)
    rs_message(0, NULL, app, "application signature incorrect");

  mpz_clear(sigv);
  mpz_clear(hashv);
  return (e ? e : e2);
}

