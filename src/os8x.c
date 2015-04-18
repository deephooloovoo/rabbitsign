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
#include "md5.h"

/*
 * Check/fix OS header fields and data.
 *
 * The OS header is much simpler than an application header, and its
 * correctness is not as crucial to validation.  The most important
 * parts of the OS header are the key ID and (for newer calculators)
 * the hardware compatibility level.  There is no date stamp required.
 * The page count is not required, and if present, is used only to
 * display the transfer percentage (when using the 84+ boot code.)
 *
 * TI only sets the OS and program image size fields in their TI-73 OS
 * headers.  (Bizarrely, they are set in the true OS header, but not
 * in the fake OS header that is transferred to page 1A.  Furthermore,
 * the OS size field is incorrect.)  In any case, these fields appear
 * to be ignored by all versions of the boot code.
 */
int rs_repair_ti8x_os(RSProgram* os,      /* OS */
		      unsigned int flags) /* flags */
{
  unsigned long hdrstart, hdrsize, fieldhead, fieldstart,
    fieldsize, ossize;
  unsigned char* hdr;
  int i;

  /* Pad the OS to a multiple of 16384.  (While strictly speaking we
     could get away with only padding each page to a multiple of 256,
     such "partial OSes" are not supported by most linking
     software.) */

  rs_program_set_length(os, ((os->length + 0x3fff) & ~0x3fff));

  /* If no OS header was provided in the input, try to get a header
     from page 1A instead */

  if (os->header_length < 6
      || os->header[0] != 0x80
      || os->header[1] != 0x0f) {
    for (i = 0; i < os->npagenums; i++) {
      if (os->pagenums[i] == 0x1a) {
	rs_free(os->header);
	if (!(os->header = rs_malloc(256)))
	  return RS_ERR_OUT_OF_MEMORY;
	memcpy(os->header, os->data + ((unsigned long) i << 14), 256);
	os->header_length = 256;
	break;
      }
    }
  }

  /* Clear old header/signature (not done on the TI-73 because
     official TI-73 OSes contain a fake header; I don't recommend
     doing this for third-party OSes) */

  if (os->calctype != RS_CALC_TI73)
    for (i = 0; i < os->npagenums; i++)
      if (os->pagenums[i] == 0x1a)
	memset(os->data + ((unsigned long) i << 14), 0xff, 512);

  /* Fix header size.  OS headers must always begin with an 800x field
     and end with an 807x field (TI always uses 800F and 807F, as for
     apps; I'm not sure whether it's required.) */

  if (os->header_length < 6
      || os->header[0] != 0x80
      || (os->header[1] & 0xf0) != 0) {
    rs_error(NULL, os, "no OS header found");
    return RS_ERR_MISSING_HEADER;
  }

  rs_get_field_size(os->header, &hdrstart, NULL);
  hdr = os->header + hdrstart;
  hdrsize = os->header_length - hdrstart;

  if (rs_find_app_field(0x8070, hdr, hdrsize,
			&fieldhead, &fieldstart, &fieldsize)) {
    rs_error(NULL, os, "OS header has no program image field");
    return RS_ERR_MISSING_PROGRAM_IMAGE;
  }

  hdrsize = fieldstart;
  os->header_length = hdrstart + hdrsize;

  if ((os->header_length % 64) == 55) {
    if (flags & RS_IGNORE_ALL_WARNINGS) {
      rs_warning(NULL, os, "OS header has length 55 mod 64");
      rs_warning(NULL, os, "(this will fail to validate on TI-83+ BE)");
    }
    else {
      rs_error(NULL, os, "OS header has length 55 mod 64");
      rs_error(NULL, os, "(this will fail to validate on TI-83+ BE)");
      return RS_ERR_INVALID_PROGRAM_SIZE;
    }
  }

  /* Fix OS / OS image sizes if requested */

  if (flags & RS_FIX_OS_SIZE) {
    ossize = os->length + hdrsize;
    if (rs_set_field_size(os->header, ossize)) {
      rs_error(NULL, os, "cannot set OS length");
      return RS_ERR_FIELD_TOO_SMALL;
    }

    if (rs_set_field_size(hdr + fieldhead, os->length)) {
      rs_error(NULL, os, "cannot set OS image length");
      return RS_ERR_FIELD_TOO_SMALL;
    }
  }

  /* Check for key ID */

  if (rs_find_app_field(0x8010, hdr, hdrsize, NULL, NULL, NULL)) {
    if (flags & RS_IGNORE_ALL_WARNINGS) 
      rs_warning(NULL, os, "OS header has no key ID field");
    else {
      rs_error(NULL, os, "OS header has no key ID field");
      return RS_ERR_MISSING_KEY_ID;
    }
  }

  /* Check/fix page count */

  if (rs_find_app_field(0x8080, hdr, hdrsize,
			NULL, &fieldstart, &fieldsize)) {
    if (os->length != 14 * 0x4000L) {
      rs_warning(NULL, os, "OS header has no page count field");
    }
  }
  else if (fieldsize != 1) {
    rs_warning(NULL, os, "OS header has an invalid page count field");
  }
  else if (flags & RS_FIX_PAGE_COUNT) {
    hdr[fieldstart] = os->length >> 14;
  }
  else if (hdr[fieldstart] != (os->length >> 14)) {
    rs_warning(NULL, os, "OS header has an incorrect page count field");
  }

  /* Check and reset validation flag bytes */

  if (os->data[0x56] != 0xff && os->data[0x56] != 0x5a) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, os, "OS has invalid data at 0056h");
    else {
      rs_error(NULL, os, "OS has invalid data at 0056h");
      return RS_ERR_INVALID_PROGRAM_DATA;
    }
  }

  if (os->data[0x56] == 0x5a)
    os->data[0x56] = 0xff;

  if (os->data[0x57] != 0xff && os->data[0x57] != 0xa5) {
    if (flags & RS_IGNORE_ALL_WARNINGS)
      rs_warning(NULL, os, "OS has invalid data at 0057h");
    else {
      rs_error(NULL, os, "OS has invalid data at 0057h");
      return RS_ERR_INVALID_PROGRAM_DATA;
    }
  }

  if (os->data[0x57] == 0xff)
    os->data[0x57] = 0xa5;

  return RS_SUCCESS;
}

/*
 * Compute signature for an OS.
 */
int rs_sign_ti8x_os(RSProgram* os, /* OS */
		    RSKey* key)	   /* signing key */
{
  struct md5_ctx ctx;
  md5_uint32 hash[4];
  mpz_t hashv, sigv;
  unsigned char sigdata[512];
  size_t siglength;
  int e;

  md5_init_ctx(&ctx);
  md5_process_bytes(os->header, os->header_length, &ctx);
  md5_process_bytes(os->data, os->length, &ctx);
  md5_finish_ctx(&ctx, hash);

  mpz_init(hashv);
  mpz_init(sigv);

  mpz_import(hashv, 16, -1, 1, 0, 0, hash);
  rs_message(2, NULL, os, "hash = %ZX", hashv);

  if ((e = rs_sign_rsa(sigv, hashv, key))) {
    mpz_clear(hashv);
    mpz_clear(sigv);
    return e;
  }

  rs_message(2, NULL, os, "sig = %ZX", sigv);

  sigdata[0] = 0x02;
  //sigdata[1] = 0xd;
  sigdata[1]=0x3e;

  mpz_export(sigdata + 4, &siglength, -1, 1, 0, 0, sigv);
  sigdata[2]=(siglength>>8)&&0xff;
  sigdata[3] = siglength & 0xff;
  siglength += 4;

//  while (siglength < 96)
//    sigdata[siglength++] = 0xff;

  rs_free(os->signature);
  if (!(os->signature = rs_malloc(siglength)))
    return RS_ERR_OUT_OF_MEMORY;

  memcpy(os->signature, sigdata, siglength);
  os->signature_length = siglength;
  return RS_SUCCESS;
}

/*
 * Validate OS signature.
 */
int rs_validate_ti8x_os(const RSProgram* os,
			const RSKey* key)
{
  unsigned long fieldstart, fieldsize;
  struct md5_ctx ctx;
  md5_uint32 hash[4];
  mpz_t hashv, sigv;
  int e;

  if (os->signature_length < 3) {
    rs_error(NULL, os, "OS does not have a signature");
    return RS_ERR_MISSING_RSA_SIGNATURE;
  }

  if (os->signature[0] != 0x02 || (( (os->signature[1] & 0xf0) != 0x00) && ( (os->signature[1] & 0xf0) !=0x30))){
    rs_error(NULL, os, "OS does not have an RSA signature");
    return RS_ERR_MISSING_RSA_SIGNATURE;
  }
  rs_get_field_size(os->signature, &fieldstart, &fieldsize);

  md5_init_ctx(&ctx);
  md5_process_bytes(os->header, os->header_length, &ctx);
  md5_process_bytes(os->data, os->length, &ctx);
  md5_finish_ctx(&ctx, hash);

  mpz_init(hashv);
  mpz_init(sigv);

  mpz_import(hashv, 16, -1, 1, 0, 0, hash);
  rs_message(2, NULL, os, "hash = %ZX", hashv);

  mpz_import(sigv, fieldsize, -1, 1, 0, 0, os->signature + fieldstart);
  rs_message(2, NULL, os, "sig = %ZX", sigv);

  e = rs_validate_rsa(sigv, hashv, key);
  if (e == RS_SIGNATURE_INCORRECT)
    rs_message(0, NULL, os, "OS signature incorrect");

  mpz_clear(hashv);
  mpz_clear(sigv);
  return e;
}
