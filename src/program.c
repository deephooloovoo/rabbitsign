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
 * Create a new program.
 */
RSProgram* rs_program_new()
{
  RSProgram* prgm = rs_malloc(sizeof(RSProgram));

  if (!prgm)
    return NULL;

  prgm->filename = NULL;
  prgm->calctype = 0;
  prgm->datatype = 0;
  prgm->data = NULL;
  prgm->length = 0;
  prgm->length_a = 0;
  prgm->header = NULL;
  prgm->header_length = 0;
  prgm->signature = NULL;
  prgm->signature_length = 0;
  prgm->pagenums = NULL;
  prgm->npagenums = 0;

  return prgm;
}

/*
 * Create a new program by wrapping an existing data buffer.
 *
 * If buffer_size is zero, data will be copied from the source buffer
 * into the new program.
 *
 * If buffer_size is nonzero, then the source buffer must have been
 * allocated using malloc(); buffer_size is the total amount of memory
 * allocated.  The data will not be copied, and the new program object
 * assumes ownership of the buffer.
 */
RSProgram* rs_program_new_with_data(RSCalcType ctype, /* calc type */
				    RSDataType dtype, /* data type */
				    void* data,	      /* source buffer */
				    unsigned long length, /* length of data */
				    unsigned long buffer_size) /* amount of
								  memory
								  allocated */
{
  RSProgram* prgm = rs_program_new();

  if (!prgm)
    return NULL;

  prgm->calctype = ctype;
  prgm->datatype = dtype;

  if (data) {
    if (buffer_size) {
      prgm->data = data;
      prgm->length = length;
      prgm->length_a = buffer_size;
    }
    else {
      if (rs_program_append_data(prgm, data, length)) {
	rs_program_free(prgm);
	return NULL;
      }
    }
  }

  return prgm;
}

/*
 * Free program data.
 */
void rs_program_free(RSProgram* prgm)
{
  if (!prgm)
    return;

  rs_free(prgm->filename);
  rs_free(prgm->data);
  rs_free(prgm->header);
  rs_free(prgm->signature);
  rs_free(prgm->pagenums);
  rs_free(prgm);
}

/*
 * Truncate or extend program.
 *
 * If length is less than the program's current length, the program is
 * truncated.  If length is greater than the current size of the
 * program, additional space is added.  The extra space is padded with
 * 0xFF, with the exception of bytes that fall at the start of a page.
 */
int rs_program_set_length(RSProgram* prgm,	/* program */
			  unsigned long length) /* new length of program */
{
  unsigned long length_a, i;
  unsigned char* dptr;

  if (length <= prgm->length) {
    prgm->length = length;
    return RS_SUCCESS;
  }
  else {
    if (length > prgm->length_a) {
      length_a = length + 16384;

      dptr = rs_realloc(prgm->data, length_a);
      if (!dptr)
	return RS_ERR_OUT_OF_MEMORY;
      prgm->data = dptr;
      prgm->length_a = length_a;
    }
    
    memset(prgm->data + prgm->length, 0xff, length - prgm->length);

    for (i = ((prgm->length + 0x3fff) & ~0x3fff);
	 i < length;
	 i += 0x4000)
      prgm->data[i] = 0x42;

    prgm->length = length;
    return RS_SUCCESS;
  }
}

/*
 * Add data to the end of the program.
 */
int rs_program_append_data(RSProgram* prgm,           /* program */
			   const unsigned char* data, /* data */
			   unsigned long length)      /* size of data */
{
  unsigned long nlength, length_a;
  unsigned char* dptr;

  nlength = prgm->length + length;
  if (nlength > prgm->length_a) {
    length_a = nlength + 16384;

    dptr = rs_realloc(prgm->data, length_a);
    if (!dptr)
      return RS_ERR_OUT_OF_MEMORY;
    prgm->data = dptr;
    prgm->length_a = length_a;
  }
    
  memcpy(prgm->data + prgm->length, data, length);
  prgm->length = nlength;
  return RS_SUCCESS;
}
