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
 * Write program to a .89k/.89u/.9xk/.9xu file.
 *
 * If month = day = year = 0, use the current time.
 *
 * Note: on platforms where it matters, all output files must be
 * opened in "binary" mode.
 */
int rs_write_ti9x_file(const RSProgram* prgm, /* program */
		       FILE* outfile,	      /* output file */
		       int month,	      /* timestamp month */
		       int day,		      /* timestamp day */
		       int year,	      /* timestamp year*/
		       unsigned int flags RS_ATTR_UNUSED)
{
  const unsigned char *hdr;
  unsigned long hdrstart, hdrsize, fieldstart, fieldsize;
  char name[9];
  int e;

  if (prgm->length >= 6) {
    rs_get_field_size(prgm->data, &hdrstart, &hdrsize);
    hdr = prgm->data + hdrstart;
    if (hdrsize > 128)
      hdrsize = 128;

    if (prgm->datatype == RS_DATA_OS) {
      strcpy(name, "basecode");
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
    name[0] = 0;
  }

  /* Note: the "version" header fields used in TI's 68k apps and
     OSes seem to have no relation to the actual version numbers. */

  if ((e = rs_write_tifl_header(outfile, 0, 0, 0,
				month, day, year, name,
				prgm->calctype, prgm->datatype,
				prgm->length)))
    return e;

  if (fwrite(prgm->data, 1, prgm->length, outfile) != prgm->length) {
    rs_error(NULL, NULL, "file I/O error");
    return RS_ERR_FILE_IO;
  }

  return RS_SUCCESS;
}

