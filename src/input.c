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
 * Determine the type of an unknown program, if possible.
 */
static void guess_type(RSProgram* prgm, int is_hex)
{
  const unsigned char* hdr;
  unsigned long hdrstart, hdrsize, keyid, fieldstart, fieldsize;
  prgm->keytype=RS_KEY_MD5;
  /* Z80 OSes have a detached program header */

  if (prgm->header_length > 2 && ( prgm->header[0] == 0x80 || prgm->header[0] == 0x81)) {
    rs_get_field_size(prgm->header, &hdrstart, NULL);
    hdr = prgm->header + hdrstart;
    hdrsize = prgm->header_length - hdrstart;
    keyid = rs_get_numeric_field(0x8010, hdr, hdrsize);

    prgm->datatype = RS_DATA_OS;

    if ((keyid & 0xff) == 0x02) {
      prgm->calctype = RS_CALC_TI73;
    }
    else {
      prgm->calctype = RS_CALC_TI83P;
    }
  }
  else if (prgm->length > 2) {
    rs_get_field_size(prgm->data, &hdrstart, NULL);
    hdr = prgm->data + hdrstart;
    hdrsize = prgm->length - hdrstart;
    if (hdrsize > 128)
      hdrsize = 128;

    /* Z80 apps and 68k OSes have field type 0x8000 */

    if (prgm->data[0] == 0x80 && (prgm->data[1] & 0xf0) == 0x00) {
      keyid = rs_get_numeric_field(0x8010, hdr, hdrsize);

      switch (keyid & 0xff) {
      case 0x02:
	prgm->calctype = RS_CALC_TI73;
	prgm->datatype = RS_DATA_APP;
	break;

      case 0x04:
      case 0x0A:
	prgm->calctype = RS_CALC_TI83P;
	prgm->datatype = RS_DATA_APP;
	break;

      case 0x03:
      case 0x09:
	prgm->calctype = RS_CALC_TI89;
	prgm->datatype = RS_DATA_OS;
	break;

      case 0x01:
      case 0x08:
	prgm->calctype = RS_CALC_TI92P;
	prgm->datatype = RS_DATA_OS;
	break;
      case 0x13:
    prgm->keytype = RS_KEY_SHA256;
    prgm->calctype = RS_CALC_TI83P;
    prgm->datatype = RS_DATA_OS;
    break;

      default:
	if (is_hex) {
	  prgm->calctype = RS_CALC_TI83P;
	  prgm->datatype = RS_DATA_APP;
	}
	break;
      }
    }

    /* 68k apps have field type 0x8100 */

    else if (prgm->data[0] == 0x81 && (prgm->data[1] & 0xf0) == 0x00) {
      keyid = rs_get_numeric_field(0x8110, hdr, hdrsize);
      prgm->datatype = RS_DATA_APP;

      switch (keyid & 0xff) {
      case 0x03:
      case 0x09:
	prgm->calctype = RS_CALC_TI89;
	break;

      case 0x01:
      case 0x08:
	prgm->calctype = RS_CALC_TI92P;
	break;
      case 0x13:
    prgm->keytype = RS_KEY_SHA256;
    prgm->calctype = RS_CALC_TI83P;
    prgm->datatype = RS_DATA_APP;
    break;
      }
    }

    /* Certificates have field type 0x0300 */

    else if (prgm->data[0] == 0x03 && (prgm->data[1] & 0xf0) == 0x00) {
      prgm->datatype = RS_DATA_CERT;

      if (!rs_find_app_field(0x0400, hdr, hdrsize,
			     NULL, &fieldstart, &fieldsize)
	  && fieldsize >= 1) {
	switch (hdr[fieldstart]) {
	case 0x02:
	  prgm->calctype = RS_CALC_TI73;
	  break;

	case 0x04:
	case 0x0A:
	  prgm->calctype = RS_CALC_TI83P;
	  break;

	case 0x03:
	case 0x09:
	  prgm->calctype = RS_CALC_TI89;
	  break;

	case 0x01:
	case 0x08:
	  prgm->calctype = RS_CALC_TI92P;
	  break;
	}
      }
    }
  }
}

/*
 * Read the contents of a binary file into an RSProgram.
 */
static int read_file_binary(RSProgram* prgm,
			    FILE* f,
			    unsigned long filesize)
{
  unsigned char buf[1024];
  size_t count;
  unsigned long fieldstart,fieldsize;

  if (filesize) {
    while (filesize > 0) {
      if (filesize > 1024)
	count = fread(buf, 1, 1024, f);
      else
	count = fread(buf, 1, filesize, f);

      if (count > 0)
	rs_program_append_data(prgm, buf, count);
      else
	break;

      filesize -= count;
    }
  }
  else {
    do {
      count = fread(buf, 1, 1024, f);
      if (count > 0) {
	rs_program_append_data(prgm, buf, count);
      }
    } while (count > 0);
  }
  rs_get_field_size(prgm->data, &fieldstart, &fieldsize);
  //prgm->length=fieldsize+fieldstart;
  //prgm->signature=prgm->data+fieldsize+fieldstart;
  //rs_get_field_size(prgm->signature, &fieldstart, &fieldsize);
  //prgm->signature_length=fieldsize+fieldstart;
  if (!prgm->calctype || !prgm->datatype)
    guess_type(prgm, 0);
  return RS_SUCCESS;
}

/*
 * Find a given page in the list of page numbers (or add it to the
 * end.)
 */
static int getpageidx(RSProgram* prgm,	    /* program */
		      unsigned int pagenum) /* page number */
{
  int i;
  unsigned int* array;

  for (i = 0; i < prgm->npagenums; i++)
    if (prgm->pagenums[i] == pagenum)
      return i;

  if (!(array = rs_realloc(prgm->pagenums, (i + 1) * sizeof(unsigned int))))
    return 0;
  prgm->pagenums = array;
  prgm->npagenums = i + 1;
  prgm->pagenums[i] = pagenum;
  return i;
}

/*
 * Read an Intel/TI hex file into an RSProgram.
 *
 * Note that the first ':' is assumed to have been read already.
 */
static int read_file_hex(RSProgram* prgm,
			 FILE* f,
			 unsigned int flags)
{
  int c;
  unsigned int nbytes, addr, rectype, sum, i, b, value;
  unsigned int pagenum = 0, pageidx = 0, lastaddr = 0;
  unsigned long offset;
  unsigned char data[256];
  unsigned char* sigp;
  int nparts = 0;
  int possibly_os_header = 1;

  rs_free(prgm->pagenums);
  if (!(prgm->pagenums = rs_malloc(sizeof(unsigned int))))
    return RS_ERR_OUT_OF_MEMORY;
  prgm->pagenums[0] = 0;
  prgm->npagenums = 1;

  while (!feof(f) && !ferror(f)) {
    if (3 > fscanf(f, "%2X%4X%2X", &nbytes, &addr, &rectype)) {
      rs_error(NULL, prgm, "invalid hex data (following %X:%X)",
	       pagenum, lastaddr);
      return RS_ERR_HEX_SYNTAX;
    }

    /* Read data bytes */

    sum = nbytes + addr + (addr >> 8) + rectype;
    value = 0;
    for (i = 0; i < nbytes; i++) {
      if (1 > fscanf(f, "%2X", &b)) {
	rs_error(NULL, prgm, "invalid hex data (at %X:%X)",
		 pagenum, addr);
	return RS_ERR_HEX_SYNTAX;
      }
      data[i] = b;
      sum += b;
      value = (value << 8) + b;
    }

    /* Read checksum */

    c = fgetc(f);
    if (c == 'X') {
      c = fgetc(f);
      if (c != 'X') {
	rs_error(NULL, prgm, "invalid hex data (at %X:%X)",
		 pagenum, addr);
	return RS_ERR_HEX_SYNTAX;
      }
    }
    else {
      ungetc(c, f);
      if (1 > fscanf(f, "%2X", &b)) {
	rs_error(NULL, prgm, "invalid hex data (at %X:%X)",
		 pagenum, addr);
	return RS_ERR_HEX_SYNTAX;
      }
      sum += b;
      if (sum & 0xff)
	rs_warning(NULL, prgm, "incorrect checksum (at %X:%X)",
		   pagenum, addr);
    }

    if (rectype == 0 && nbytes > 0) {
      /* Record type 0: program data */

      if (addr & 0xff00)
	possibly_os_header = 0;

      addr &= 0x3fff;

      /* if program does not start at addr 0000 (or 4000), assume
	 unsorted */
      if (addr && prgm->length == 0)
	flags &= ~RS_INPUT_SORTED;

      if ((flags & RS_INPUT_SORTED) && !addr && lastaddr) {
	/* automatically switch to next page */
	pagenum++;
	pageidx = getpageidx(prgm, pagenum);
	if (!pageidx)
	  return RS_ERR_OUT_OF_MEMORY;
      }
      else if (addr < lastaddr)
	flags &= ~RS_INPUT_SORTED;

      if (nparts == 2 && prgm->header_length) {
	/* Reading an OS signature */
	if (addr + nbytes > prgm->signature_length) {
	  if (!(sigp = rs_realloc(prgm->signature, addr + nbytes)))
	    return RS_ERR_OUT_OF_MEMORY;

	  prgm->signature = sigp;
	  if (addr > prgm->signature_length) {
	    memset(prgm->signature + prgm->signature_length, 0xff,
		   addr - prgm->signature_length);
	  }
	  prgm->signature_length = addr + nbytes;
	}
	memcpy(prgm->signature + addr, data, nbytes);
      }
      else {
	/* Reading normal program data */
	offset = ((unsigned long) pageidx << 14) | addr;
	if (offset + nbytes <= prgm->length) {
	  memcpy(prgm->data + offset, data, nbytes);
	}
	else {
	  rs_program_set_length(prgm, offset);
	  rs_program_append_data(prgm, data, nbytes);
	}
      }

      lastaddr = addr;
    }
    else if (rectype == 1) {
      /* Record type 1: "end of file" */
      nparts++;
      if (nparts == 3 && prgm->header_length)
	break;
    }
    else if (rectype == 2 || rectype == 4) {
      /* Record type 2 or 4: extended address */
      possibly_os_header = 0;
      flags &= ~RS_INPUT_SORTED;
      if (nparts < 2) {
	pagenum = value;
	pageidx = getpageidx(prgm, pagenum);
	if (pagenum && !pageidx)
	  return RS_ERR_OUT_OF_MEMORY;
      }
    }

    do {
      c = fgetc(f);
    } while (c == '\n' || c == '\r' || c == ' ');

    if (c == EOF)
      break;
    else if (c != ':') {
      if (rectype == 1)
	break;
      else {
	rs_error(NULL, prgm, "invalid hex data (following %X:%X)",
		 pagenum, lastaddr);
	return RS_ERR_HEX_SYNTAX;
      }
    }

    if (rectype == 1 && nparts == 1 && prgm->length > 0
	&& possibly_os_header) {
      /* Just finished reading OS header */
      flags &= ~RS_INPUT_SORTED;
      pagenum = pageidx = 0;

      rs_free(prgm->header);
      if (!(prgm->header = rs_malloc(prgm->length)))
	return RS_ERR_OUT_OF_MEMORY;

      memcpy(prgm->header, prgm->data, prgm->length);
      prgm->header_length = prgm->length;
      prgm->length = 0;
      possibly_os_header = 0;
    }
  }

  if (!prgm->calctype || !prgm->datatype)
    guess_type(prgm, 1);
  return RS_SUCCESS;
}

/*
 * Check if calc/data type matches expected type (or any recognized
 * type, if none was specified.)
 */
static int check_tifl_type(int calctype,
			   int datatype,
			   int calctype_expected,
			   int datatype_expected)
{
  if (calctype_expected) {
    if (calctype_expected != calctype)
      return 0;
  }
  else {
    if (calctype != RS_CALC_TI73 && calctype != RS_CALC_TI83P
	&& calctype != RS_CALC_TI89 && calctype != RS_CALC_TI92P)
      return 0;
  }

  if (datatype_expected) {
    if (datatype_expected != datatype)
      return 0;
  }
  else {
    if (datatype != RS_DATA_APP && datatype != RS_DATA_OS)
      return 0;
  }

  return 1;
}

/*
 * Read program contents from a file.
 *
 * Various file formats are supported:
 *
 * - Raw binary (must begin with the value 0x80 or 0x81)
 * - Plain Intel/TI hex
 * - Binary TIFL (89k, 89u, ...)
 * - Hex TIFL (8xk, 8xu, ...)
 *
 * Note: on platforms where it matters, all input files must be opened
 * in "binary" mode.
 */
int rs_read_program_file(RSProgram* prgm,    /* program */
			 FILE* f,	     /* file */
			 const char* fname,  /* file name */
			 unsigned int flags) /* option flags */
{
  int c;
  unsigned char tiflbuf[78];
  unsigned long tiflsize, i;
  int e;

  rs_program_set_length(prgm, 0);
  prgm->header_length = 0;
  prgm->signature_length = 0;
  prgm->npagenums = 0;

  rs_free(prgm->filename);
  prgm->filename = rs_strdup(fname);
  if (fname && !prgm->filename)
    return RS_ERR_OUT_OF_MEMORY;

  if (flags & RS_INPUT_BINARY)
    return read_file_binary(prgm, f, 0);

  c = fgetc(f);
  if (c == 0x80 || c == 0x81) {
    tiflbuf[0] = c;
    if ((e = rs_program_append_data(prgm, tiflbuf, 1)))
      return e;
    return read_file_binary(prgm, f, 0);
  }

  while (!feof(f) && !ferror(f)) {
    if (c == ':') {
      return read_file_hex(prgm, f, flags);
    }
    else if (c == '*') {
      if (fread(tiflbuf, 1, 78, f) < 78
	  || strncmp((char*) tiflbuf, "*TIFL**", 7)) {
	rs_error(NULL, prgm, "unknown input file format");
	return RS_ERR_UNKNOWN_FILE_FORMAT;
      }

      tiflsize = ((unsigned long) tiflbuf[73]
		  | ((unsigned long) tiflbuf[74] << 8)
		  | ((unsigned long) tiflbuf[75] << 16)
		  | ((unsigned long) tiflbuf[76] << 24));

      if (check_tifl_type(tiflbuf[47], tiflbuf[48],
			  prgm->calctype, prgm->datatype)) {
    if (tiflbuf[0x48] == 0x13) {
      prgm->keytype = RS_KEY_SHA256;
    } else {
      prgm->keytype = RS_KEY_MD5;
    }
	prgm->calctype = tiflbuf[47];
	prgm->datatype = tiflbuf[48];

	if (tiflbuf[77] == ':')
	  return read_file_hex(prgm, f, 0);
	else {
	  if ((e = rs_program_append_data(prgm, tiflbuf + 77, 1)))
	    return e;
	  return read_file_binary(prgm, f, tiflsize ? tiflsize - 1 : 0);
	}
      }
      else {
	/* extra data (license, certificate, etc.) -- ignore */
	if (fseek(f, tiflsize - 1, SEEK_CUR)) {
	  for (i = 0; i < tiflsize - 1; i++) {
	    if (fgetc(f) == EOF) {
	      rs_error(NULL, prgm, "unexpected EOF");
	      return RS_ERR_UNKNOWN_FILE_FORMAT;
	    }
	  }
	}
      }
    }

    c = fgetc(f);
  }

  rs_error(NULL, prgm, "unknown input file format");
  return RS_ERR_UNKNOWN_FILE_FORMAT;
}

