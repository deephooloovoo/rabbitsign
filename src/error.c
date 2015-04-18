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
#include <stdarg.h>

#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif

#include "rabbitsign.h"
#include "internal.h"

static const char* progname;
static int verbose;
static RSMessageFunc errorfunc, messagefunc;
static void *errorfuncdata, *messagefuncdata;

void rs_set_progname(s)
     const char* s;
{
  progname = s;
}

void rs_set_verbose(v)
     int v;
{
  verbose = v;
}

void rs_set_error_func(RSMessageFunc func, void* data)
{
  errorfunc = func;
  errorfuncdata = data;
}

void rs_set_message_func(RSMessageFunc func, void* data)
{
  messagefunc = func;
  messagefuncdata = data;
}

static void print_message(const RSKey* key, const RSProgram* prgm,
			  const char* msg)
{
  if (prgm && prgm->filename)
    fprintf(stderr, "%s: ", prgm->filename);
  else if (key && key->filename)
    fprintf(stderr, "%s: ", key->filename);
  else if (progname)
    fprintf(stderr, "%s: ", progname);
  fputs(msg, stderr);
  fputc('\n', stderr);
}

/* Display a critical error */
void rs_error(const RSKey* key, const RSProgram* prgm, const char* fmt, ...)
{
  char msg[512];
  va_list ap;

  va_start(ap, fmt);
  strcpy(msg, "error: ");
  rs_vsnprintf(msg + 7, sizeof(msg) - 7, fmt, ap);
  va_end(ap);

  if (errorfunc)
    (*errorfunc)(key, prgm, msg, errorfuncdata);
  else
    print_message(key, prgm, msg);
}

/* Display a warning message */
void rs_warning(const RSKey* key, const RSProgram* prgm, const char* fmt, ...)
{
  char msg[512];
  va_list ap;

  va_start(ap, fmt);
  strcpy(msg, "warning: ");
  rs_vsnprintf(msg + 9, sizeof(msg) - 9, fmt, ap);
  va_end(ap);

  if (errorfunc)
    (*errorfunc)(key, prgm, msg, errorfuncdata);
  else
    print_message(key, prgm, msg);
}

/* Display an informative message */
void rs_message(int level, const RSKey* key, const RSProgram* prgm,
		const char* fmt, ...)
{
  char msg[1024];
  va_list ap;

  if (level > verbose)
    return;

  va_start(ap, fmt);
  rs_vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  if (messagefunc)
    (*messagefunc)(key, prgm, msg, messagefuncdata);
  else
    print_message(key, prgm, msg);
}
