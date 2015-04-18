/*
 * XXK Packer
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif

#include "rabbitsign.h"
#include "internal.h"

#if !defined(strrchr) && !defined(HAVE_STRRCHR) && defined(HAVE_RINDEX)
# define strrchr rindex
#endif

static const char* getbasename(const char* f)
{
  const char *p;

  if ((p = strrchr(f, '/')))
    f = p + 1;

#if defined(__MSDOS__) || defined(__WIN32__)
  if ((p = strrchr(f, '\\')))
    f = p + 1;
#endif

  return f;
}

static const char* usage[]={
  "Usage: %s [options] app-file ...\n",
  "Where options may include:\n",
  "  -t TYPE        set program type (8xk, 73u, etc.)\n",
  "  -d MM/DD/YYYY  set application date stamp\n",
  "  -c ID          set calculator device ID\n",
  "  -o FILE        set output file\n",
  NULL};

int main(int argc, char** argv)
{
  const char* progname;
  const char* infilename = NULL;
  const char* outfilename = NULL;
  RSCalcType calctype = RS_CALC_UNKNOWN;
  RSDataType datatype = RS_DATA_UNKNOWN;
  int month = 0, day = 0, year = 0;

  FILE *infile, *outfile;
  RSProgram *prgm;
  int i, j, c, v;
  const char* arg;
  char *ptr;

  progname = getbasename(argv[0]);
  rs_set_progname(progname);
  rs_set_verbose(0);

  if (argc == 1) {
    fprintf(stderr, usage[0], progname);
    for (i = 1; usage[i]; i++)
      fputs(usage[i], stderr);
    fprintf(stderr, "Report bugs to %s.\n", PACKAGE_BUGREPORT);
    return 3;
  }

  i = j = 1;
  while ((c = rs_parse_cmdline(argc, argv, "t:d:c:o:", &i, &j, &arg))) {
    switch (c) {
    case RS_CMDLINE_HELP:
      printf(usage[0], progname);
      for (i = 1; usage[i]; i++)
	fputs(usage[i], stdout);
      printf("Report bugs to %s.\n", PACKAGE_BUGREPORT);
      return 0;

    case RS_CMDLINE_VERSION:
      printf("packxxk (%s) %s\n", PACKAGE_NAME, PACKAGE_VERSION);
      fputs("Copyright (C) 2009 Benjamin Moody\n", stdout);
      fputs("This program is free software.  ", stdout);
      fputs("There is NO WARRANTY of any kind.\n", stdout);
      return 0;

    case 't':
      /* accept '73', '83p' for compatibility with packxxk v1.x */
      if (!strcmp(arg, "73")) {
	calctype = RS_CALC_TI73;
	datatype = RS_DATA_APP;
      }
      else if (!strcmp(arg, "83p")) {
	calctype = RS_CALC_TI83P;
	datatype = RS_DATA_APP;
      }
      else if (rs_suffix_to_type(arg, &calctype, &datatype)) {
	fprintf(stderr, "%s: unknown program type %s\n", progname, arg);
	return 3;
      }
      break;

    case 'd':
      if (strrchr(arg, '/'))
	v = sscanf(arg, "%d/%d/%d", &month, &day, &year);
      else if (strrchr(arg, '-'))
	v = sscanf(arg, "%d-%d-%d", &day, &month, &year);
      else
	v = sscanf(arg, "%2d%2d%d", &month, &day, &year);
      if (v < 3) {
	fprintf(stderr, "%s: -d: invalid argument %s\n", progname, arg);
	return 3;
      }
      break;

    case 'c':
      if (!sscanf(arg, "%x", &calctype)) {
	fprintf(stderr, "%s: -c: invalid argument %s\n", progname, arg);
	return 3;
      }
      break;

    case 'o':
      outfilename = arg;
      break;

    case RS_CMDLINE_FILENAME:
      break;

    case RS_CMDLINE_ERROR:
      return 3;

    default:
      fprintf(stderr, "%s: internal error: unknown option -%c\n",
	      progname, c);
      return 5;
    }
  }

  if (outfilename == NULL || !strcmp(outfilename, "-"))
    outfile = stdout;
  else {
    if (!(outfile = fopen(outfilename, "wb"))) {
      perror(outfilename);
      fprintf(stderr, "%s: unable to open output file %s\n",
	      progname, outfilename);
      return 2;
    }
  }

  i = j = 1;
  while ((c = rs_parse_cmdline(argc, argv, "t:d:c:o:", &i, &j, &arg))) {
    if (c != RS_CMDLINE_FILENAME)
      continue;

    if (!strcmp(arg, "-")) {
      infilename = "(standard input)";
      infile = stdin;
    }
    else {
      infilename = arg;
      if (!(infile = fopen(infilename, "rb"))) {
	perror(infilename);
	fprintf(stderr, "%s: unable to open hex file %s\n",
		progname, infilename);
	return 2;
      }
    }

    prgm = rs_program_new();

    if (calctype && datatype) {
      prgm->calctype = calctype;
      prgm->datatype = datatype;
    }
    else if ((ptr = strrchr(infilename, '.'))) {
      rs_suffix_to_type(ptr + 1, &prgm->calctype, &prgm->datatype);
    }

    if (rs_read_program_file(prgm, infile, infilename, 0)) {
      rs_program_free(prgm);
      if (infile != stdin)
	fclose(infile);
      if (outfile != stdout)
	fclose(outfile);
      return 2;
    }

    if (infile != stdin)
      fclose(infile);

    if (rs_write_program_file(prgm, outfile, month, day, year, 0)) {
      rs_program_free(prgm);
      if (outfile != stdout)
	fclose(outfile);
      return 2;
    }

    rs_program_free(prgm);
  }

  if (outfile != stdout)
    fclose(outfile);

  return (i ? 2 : 0);
}


