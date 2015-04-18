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
 * Get length of a header field.
 */
void rs_get_field_size (const unsigned char* data, /* Data */
			unsigned long* fieldstart, /* Offset to start
						      of field
						      contents */
			unsigned long* fieldsize)  /* Length of field
						      contents */
{
  switch (data[1] & 0x0f) {
  case 0x0D:
    if (fieldstart) *fieldstart = 3;
    if (fieldsize) *fieldsize = data[2];
    break;

  case 0x0E:
    if (fieldstart) *fieldstart = 4;
    if (fieldsize) *fieldsize = ((data[2] << 8) | data[3]);
    break;

  case 0x0F:
    if (fieldstart) *fieldstart = 6;
    if (fieldsize) {
      *fieldsize = (((unsigned long) data[2] << 24)
		    | ((unsigned long) data[3] << 16)
		    | ((unsigned long) data[4] << 8)
		    | (unsigned long) data[5]);
    }
    break;

  default:
    if (fieldstart) *fieldstart = 2;
    if (fieldsize) *fieldsize = (data[1] & 0x0f);
    break;
  }
}

/* Set length of a header field. */
int rs_set_field_size (unsigned char* data,
		       unsigned long fieldsize)
{
  switch (data[1] & 0x0f) {
  case 0x0D:
    if (fieldsize > 0xff)
      return -1;
    data[2] = fieldsize;
    return 0;

  case 0x0E:
    if (fieldsize > 0xfffful)
      return -1;
    data[2] = (fieldsize >> 8) & 0xff;
    data[3] = fieldsize & 0xff;
    return 0;

  case 0x0F:
    if (fieldsize > 0xfffffffful)
      return -1;
    data[2] = (fieldsize >> 24) & 0xff;
    data[3] = (fieldsize >> 16) & 0xff;
    data[4] = (fieldsize >> 8) & 0xff;
    data[5] = fieldsize & 0xff;
    return 0;

  default:
    if (fieldsize > 0x0C)
      return -1;
    data[1] = (data[1] & 0xf0) | fieldsize;
    return 0;
  }
}

/*
 * Find a given header field in the data.
 */
int rs_find_app_field(unsigned int type,         /* Type of field to
						    search for (e.g.,
						    0x8040 to search
						    for the name) */
		      const unsigned char* data, /* Data to search */
		      unsigned long length,      /* Maximum length of
						    data to search */
		      unsigned long* fieldhead,	 /* Offset to field
						    type bytes, if
						    found */
		      unsigned long* fieldstart, /* Offset to start of
						    field contents, if
						    found */
		      unsigned long* fieldsize)  /* Length of field
						    contents, if
						    found */
{
  unsigned char b1, b2;
  unsigned long pos = 0;
  unsigned long fstart, fsize;

  b1 = ((type >> 8) & 0xff);
  b2 = (type & 0xf0);

  while (pos < length) {
    if (data[pos] == b1 && (data[pos + 1] & 0xf0) == b2) {
      rs_get_field_size(data + pos, &fstart, fieldsize);
      if (fieldhead) *fieldhead = pos;
      if (fieldstart) *fieldstart = pos + fstart;
      return 0;
    }

    rs_get_field_size(data + pos, &fstart, &fsize);
    pos += fstart + fsize;
  }

  return -1;
}

/*
 * Get value of a numeric header field.
 *
 * Return 0 if field is not found, or if its contents are longer than
 * 4 bytes.
 */
unsigned long rs_get_numeric_field (unsigned int type,
				    const unsigned char* data,
				    unsigned long length)
{
  unsigned long fstart, fsize, value;

  if (rs_find_app_field(type, data, length, NULL, &fstart, &fsize))
    return 0;

  if (fsize > 4)
    return 0;

  value = 0;
  while (fsize > 0) {
    value <<= 8;
    value |= data[fstart];
    fstart++;
    fsize--;
  }
  return value;
}
