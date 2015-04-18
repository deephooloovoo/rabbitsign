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
 * Write a single record to an Intel hex file.
 */
static int write_hex_record(FILE* outfile,	 /* output file */
			    unsigned int nbytes, /* number of bytes */
			    unsigned int addr,	 /* address */
			    unsigned int type,	 /* record type */
			    unsigned char* data, /* data */
			    unsigned int flags,	 /* flags */
			    int final)
{
  char buf[256];
  unsigned int i;
  unsigned int sum;

  sum = nbytes + addr + (addr >> 8) + type;
  sprintf(buf, ":%02X%04X%02X", nbytes, addr, type);

  for (i = 0; i < nbytes; i++) {
    sprintf(buf + 9 + 2 * i, "%02X", data[i]);
    sum += data[i];
  }

  sum = ((-sum) & 0xff);

  sprintf(buf + 9 + 2 * i, "%02X", sum);

  if (!final) {
    if (flags & RS_OUTPUT_APPSIGN)
      strcpy(buf + 11 + 2 * i, "\n");
    else
      strcpy(buf + 11 + 2 * i, "\r\n");
  }

  if (fputs(buf, outfile) == EOF) {
    rs_error(NULL, NULL, "file I/O error");
    return RS_ERR_FILE_IO;
  }

  return RS_SUCCESS;
}

/*
 * Write a chunk of data to an Intel hex file.
 */
static int write_hex_data(FILE* outfile,	/* output file */
			  unsigned long length, /* number of bytes */
			  unsigned long addr,	/* starting address */
			  unsigned char* data,	/* data */
			  unsigned int flags)
{
  unsigned int count;
  int e;

  while (length > 0) {
    if (length < 0x20)
      count = length;
    else
      count = 0x20;

    if ((e = write_hex_record(outfile, count, addr, 0, data, flags, 0)))
      return e;

    length -= count;
    addr += count;
    data += count;
  }

  return RS_SUCCESS;
}

/*
 * Write program to a .73k/.73u/.8xk/.8xu or .app file.
 *
 * If month = day = year = 0, use the current time.
 *
 * Note: on platforms where it matters, all output files must be
 * opened in "binary" mode.
 */
int rs_write_ti8x_file(const RSProgram* prgm,  /* program */
		       FILE* outfile,	       /* output file */
		       int month,	       /* timestamp month */
		       int day,		       /* timestamp day */
		       int year,	       /* timestamp year*/
		       unsigned int flags)     /* flags */
{
  const unsigned char *hdr;
  unsigned long hdrstart, hdrsize, fieldstart, fieldsize;
  int major, minor, i;
  unsigned long npages, nrecords, hexsize;
  char name[9];
  unsigned int pagenum, addr;
  unsigned long count;
  unsigned char pnbuf[2];
  int e;
  
  if (!(flags & RS_OUTPUT_HEX_ONLY)) {
    if (prgm->header_length) {
      hdr = prgm->header;
      hdrsize = prgm->header_length;
    }
    else {
      hdr = prgm->data;
      hdrsize = prgm->length;
    }

    if (hdrsize >= 6) {
      rs_get_field_size(hdr, &hdrstart, NULL);
      hdr += hdrstart;
      hdrsize -= hdrstart;
      if (hdrsize > 128)
	hdrsize = 128;

      major = rs_get_numeric_field(0x8020, hdr, hdrsize);
      minor = rs_get_numeric_field(0x8030, hdr, hdrsize);

      if (prgm->datatype == RS_DATA_OS) {
	if (prgm->calctype == RS_CALC_TI73)
	  strcpy(name, "BASECODE");
	else
	  strcpy(name, "basecode");
      }
      else if (!rs_find_app_field(0x8040, hdr, hdrsize,
				  NULL, &fieldstart, &fieldsize)) {
	if (fieldsize > 8)
	  fieldsize = 8;
	strncpy(name, (char*) hdr + fieldstart, fieldsize);
	name[fieldsize] = 0;
      }
       else if (!rs_find_app_field(0x8140, hdr, hdrsize,
				  NULL, &fieldstart, &fieldsize)) {
	if (fieldsize > 8)
	  fieldsize = 8;
	strncpy(name, (char*) hdr + fieldstart, fieldsize);
	name[fieldsize] = 0;
      }
      else {
	name[0] = 0;
      }
    }
    else {
      major = minor = 0;
      name[0] = 0;
    }

    npages = ((prgm->length + 0x3fff) >> 14);
    nrecords = 1 + npages + ((prgm->length + 0x1f) >> 5);

    if (prgm->header_length)
      nrecords += 1 + ((prgm->header_length + 0x1f) >> 5);
    if (prgm->signature_length)
      nrecords += 1 + ((prgm->signature_length + 0x1f) >> 5);

    if (flags & RS_OUTPUT_APPSIGN) {
      hexsize = (npages * 4
		 + prgm->length * 2
		 + prgm->header_length * 2
		 + prgm->signature_length * 2
		 + nrecords * 12 - 1);
    }
    else if (flags & RS_OUTPUT_BINARY) {
      hexsize = prgm->signature_length+prgm->length+prgm->header_length;
    }
    else {
      hexsize = (npages * 4
		 + prgm->length * 2
		 + prgm->header_length * 2
		 + prgm->signature_length * 2
		 + nrecords * 13 - 2);
    }

    if ((e = rs_write_tifl_header(outfile, !(flags & RS_OUTPUT_BINARY), major, minor,
				  month, day, year, name,
				  prgm->calctype, prgm->datatype,
				  hexsize)))
      return e;
  }
  if (flags & RS_OUTPUT_BINARY) {
    fwrite(prgm->data,1,prgm->length+prgm->header_length,outfile);
    fwrite(prgm->signature,1,prgm->signature_length,outfile);
    return 0;
  }
  if (prgm->header_length) {
    if ((e = write_hex_data(outfile, prgm->header_length, 0,
			    prgm->header, flags)))
      return e;
    if ((e = write_hex_record(outfile, 0, 0, 1, NULL, flags, 0)))
      return e;
  }

  for (i = 0; ((unsigned long) i << 14) < prgm->length; i++) {
    if (i < prgm->npagenums)
      pagenum = prgm->pagenums[i];
    else
      pagenum = i;

    if (pagenum == 0 && prgm->header_length)
      addr = 0;
    else
      addr = 0x4000;

    pnbuf[0] = (pagenum >> 8) & 0xff;
    pnbuf[1] = pagenum & 0xff;

    if ((e = write_hex_record(outfile, 2, 0, 2, pnbuf, flags, 0)))
      return e;

    count = prgm->length - i * 0x4000;
    if (count > 0x4000)
      count = 0x4000;

    if ((e = write_hex_data(outfile, count, addr,
			    prgm->data + i * 0x4000, flags)))
      return e;
  }

  if (prgm->signature_length) {
    if ((e = write_hex_record(outfile, 0, 0, 1, NULL, flags, 0)))
      return e;
    if (e = write_hex_data(outfile, prgm->signature_length, 0,
			    prgm->signature, flags))
      return e;
  }

  return write_hex_record(outfile, 0, 0, 1, NULL, flags, 1);
}

