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

#if !defined(strchr) && !defined(HAVE_STRCHR) && defined(HAVE_INDEX)
# define strchr index
#endif

/*
 * Parse and return next command line option.
 */
int rs_parse_cmdline(int argc, char** argv, const char* optstring,
		     int* i, int* j, const char** arg)
{
  char c;
  char* p;

  if (*i >= argc)
    return RS_CMDLINE_FINISHED;

  if (argv[*i][0] != '-' || argv[*i][1] == 0) {
    *arg = argv[*i];
    (*i)++;
    *j = 1;
    return RS_CMDLINE_FILENAME;
  }

  if (argv[*i][1] == '-') {
    if (!strcasecmp(argv[*i], "--help")) {
      (*i)++;
      *j = 1;
      return RS_CMDLINE_HELP;
    }
    else if (!strcasecmp(argv[*i], "--version")) {
      (*i)++;
      *j = 1;
      return RS_CMDLINE_VERSION;
    }
    else {
      rs_error(NULL, NULL, "unrecognized option %s (try --help)", argv[*i]);
      return RS_CMDLINE_ERROR;
    }
  }

  c = argv[*i][*j];

  if (c == ':' || !(p = strchr(optstring, c))) {
    rs_error(NULL, NULL, "unrecognized option -%c (try --help)", c);
    return RS_CMDLINE_ERROR;
  }

  if (p[1] == ':') {
    if (argv[*i][*j + 1]) {
      *arg = &argv[*i][*j + 1];
      (*i)++;
      *j = 1;
      return c;
    }
    else {
      (*i) += 2;
      *j = 1;
      if (*i > argc) {
	rs_error(NULL, NULL, "-%c: requires an argument", c);
	return RS_CMDLINE_ERROR;
      }
      *arg = argv[*i - 1];
      return c;
    }
  }
  else {
    if (argv[*i][*j + 1]) {
      (*j)++;
    }
    else {
      (*i)++;
      *j = 1;
    }
    *arg = NULL;
    return c;
  }
}
