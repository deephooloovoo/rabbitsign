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

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef TM_IN_SYS_TIME
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "rabbitsign.h"
#include "internal.h"

#define BCD(x) ((x) + 6 * ((x)/10))

/*
 * Write a TIFL header to a file.
 */
int rs_write_tifl_header(FILE* outfile,    /* file to write to */
			 int is_hex,	    /* is file in hex format? */
			 int major,	    /* major version # */
			 int minor,	    /* minor version # */
			 int month,	    /* current month */
			 int day,	    /* current day */
			 int year,	    /* current year */
			 const char* name, /* name of program */
			 int calctype,	    /* calculator type */
			 int datatype,	    /* data type */
			 unsigned long filesize) /* size of data */
{
  unsigned char buf[78];
  time_t t;
  struct tm* tm;

  memset(buf, 0, 78);

  strcpy((char*) buf, "**TIFL**");

  buf[8] = major;
  buf[9] = minor;

  if (is_hex) {
    buf[10] = 0x01;
    buf[11] = 0x88;
  }
  else {
    buf[10] = 0;
    buf[11] = 0;
  }

  if (!month && !day && !year) {
    time(&t);
    tm = localtime(&t);
    month = tm->tm_mon + 1;
    day = tm->tm_mday;
    year = tm->tm_year + 1900;
  }

  buf[12] = BCD(month);
  buf[13] = BCD(day);
  buf[14] = BCD(year / 100);
  buf[15] = BCD(year % 100);

  buf[16] = strlen(name);
  if (buf[16] > 8)
    buf[16] = 8;

  strncpy((char*) buf + 17, name, 8);

  buf[48] = calctype;
  buf[49] = datatype;

  buf[74] = filesize & 0xff;
  buf[75] = (filesize >> 8) & 0xff;
  buf[76] = (filesize >> 16) & 0xff;
  buf[77] = (filesize >> 24) & 0xff;

  if (fwrite(buf, 1, 78, outfile) != 78) {
    rs_error(NULL, NULL, "file I/O error");
    return RS_ERR_FILE_IO;
  }

  return RS_SUCCESS;
}

