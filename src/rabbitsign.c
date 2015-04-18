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

#if !defined(strcasecmp) && !defined(HAVE_STRCASECMP)
# ifdef HAVE_STRICMP
#  define strcasecmp stricmp
# else
#  define strcasecmp strcmp
# endif
#endif

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
  "   -a:          appsign compatibility mode (Unix-style output)\n",
  "   -b:          read raw binary data (default: auto-detect)\n",
  "   -c:          check existing app signatures rather than signing\n",
  "   -f:          force signing despite errors\n",
  "   -g:          write app in GraphLink (XXk) format\n",
  "   -k KEYFILE:  use specified key file\n",
  "   -K NUM:      use specified key ID (hexadecimal)\n",
  "   -n:          do not alter the app header\n",
  "   -o OUTFILE:  write to specified output file (default is <name>.app\n",
  "                or <name>.8xk)\n",
  "   -p:          fix the pages field if found\n",
  "   -P:          add an extra page if necessary\n",
  "   -q:          suppress warning messages\n",
  "   -r:          re-sign a previously signed app (i.e. strip off all\n",
  "                data beyond that indicated by the size header)\n",
  "   -R R:        specify the root to use (0, 1, 2, or 3) (default is 0)\n",
  "   -t TYPE:     specify program type (e.g. 8xk, 73u)\n",
  "   -u:          assume plain hex input is unsorted (default is sorted)\n",
  "   -v:          be verbose (-vv for even more verbosity)\n",
  "   --help:      describe options\n",
  "   --version:   print version info\n",
  NULL};

int main(int argc, char** argv)
{
  unsigned int flags = (RS_INPUT_SORTED | RS_OUTPUT_HEX_ONLY);

  int rootnum = 0;		/* which of the four valid signatures
				   to generate

				   0 = standard (r,s)
				   1 = (-r,s)
				   2 = (r,-s)
				   3 = (-r,-s) */

  int rawmode = 0;		/* 0 = fix app headers
				   1 = sign "raw" data */

  int valmode = 0;		/* 0 = sign apps
				   1 = validate apps */

  const char* infilename;	/* file name for input */

  const char* outfilename = NULL; /* file name for output */

  const char* keyfilename = NULL; /* file name for key */

  int verbose = 0;		/* -1 = quiet (errors only)
				   0 = default (warnings + errors)
				   1 = verbose (print file names / status)
				   2 = very verbose (details of computation) */

  static const char optstring[] = "abBcfgk:K:no:pPqrR:t:uv";
  const char *progname;
  int i, j, c, e;
  const char* arg;
  char *tempname;

  FILE* infile;
  FILE* outfile;
  RSKey* key;
  RSProgram* prgm;
  unsigned long keyid = 0, appkeyid;
  RSCalcType ctype = RS_CALC_UNKNOWN;
  RSDataType dtype = RS_DATA_UNKNOWN;

  char *ptr;
  const char *ext;
  int invalidapps = 0;

  progname = getbasename(argv[0]);
  rs_set_progname(progname);

  if (argc == 1) {
    fprintf(stderr, usage[0], progname);
    for (i = 1; usage[i]; i++)
      fputs(usage[i], stderr);
    fprintf(stderr, "Report bugs to %s.\n", PACKAGE_BUGREPORT);
    return 5;
  }

  i = j = 1;
  while ((c = rs_parse_cmdline(argc, argv, optstring, &i, &j, &arg))) {
    switch (c) {
    case RS_CMDLINE_HELP:
      printf(usage[0], progname);
      for (i = 1; usage[i]; i++)
	fputs(usage[i], stdout);
      printf("Report bugs to %s.\n", PACKAGE_BUGREPORT);
      return 0;

    case RS_CMDLINE_VERSION:
      printf("%s\n", PACKAGE_STRING);
      fputs("Copyright (C) 2009 Benjamin Moody\n", stdout);
      fputs("This program is free software.  ", stdout);
      fputs("There is NO WARRANTY of any kind.\n", stdout);
      return 0;

    case 'o':
      outfilename = arg;
      break;

    case 'k':
      keyfilename = arg;
      break;

    case 'K':
      if (!sscanf(arg, "%lx", &keyid)) {
	fprintf(stderr, "%s: -K: invalid argument %s\n", progname, arg);
	return 5;
      }
      break;

    case 'b':
      flags |= RS_INPUT_BINARY;
      break;

    case 'u':
      flags &= ~RS_INPUT_SORTED;
      break;

    case 'f':
      flags |= RS_IGNORE_ALL_WARNINGS;
      break;

    case 'g':
      flags &= ~RS_OUTPUT_HEX_ONLY;
      break;

    case 'B':
      flags |= RS_OUTPUT_BINARY;
      break;

    case 'a':
      flags |= RS_OUTPUT_APPSIGN;
      break;

    case 'R':
      if (!sscanf(arg, "%d", &rootnum)) {
	fprintf(stderr, "%s: -R: invalid argument %s\n", progname, arg);
	return 5;
      }
      break;

    case 't':
      if (rs_suffix_to_type(arg, &ctype, &dtype)) {
	fprintf(stderr, "%s: unrecognized file type %s\n", progname, arg);
	return 5;
      }
      break;

    case 'n':
      rawmode = 1;
      break;
 
    case 'r':
      flags |= RS_REMOVE_OLD_SIGNATURE;
      break;

    case 'P':
      flags |= RS_ZEALOUSLY_PAD_APP;
      break;

    case 'p':
      flags |= RS_FIX_PAGE_COUNT;
      break;

    case 'c':
      valmode = 1;
      break;

    case 'v':
      verbose++;
      break;

    case 'q':
      verbose--;
      break;

    case RS_CMDLINE_FILENAME:
      break;

    case RS_CMDLINE_ERROR:
      return 5;

    default:
      fprintf(stderr, "%s: internal error: unknown option -%c\n",
	      progname, c);
      abort();
    }
  }

  rs_set_verbose(verbose);

  if (outfilename && (ptr = strrchr(outfilename, '.'))
      && !rs_suffix_to_type(ptr + 1, NULL, NULL))
    flags &= ~RS_OUTPUT_HEX_ONLY;


  /* Read key file (if manually specified) */

  key = rs_key_new();

  if (keyfilename) {
    infile = fopen(keyfilename, "rb");
    if (!infile) {
      perror(keyfilename);
      rs_key_free(key);
      return 3;
    }
    if (rs_read_key_file(key, infile, keyfilename, 1)) {
      fclose(infile);
      rs_key_free(key);
      return 3;
    }
    fclose(infile);
  }
  else if (keyid) {
    if (rs_key_find_for_id(key, keyid, valmode)) {
      rs_key_free(key);
      return 3;
    }
  }

  /* Process applications */

  i = j = 1;
  while ((c = rs_parse_cmdline(argc, argv, optstring, &i, &j, &arg))) {
    if (c != RS_CMDLINE_FILENAME)
      continue;

    /* Read input file */

    if (strcmp(arg, "-")) {
      infilename = arg;
      infile = fopen(arg, "rb");
      if (!infile) {
	perror(arg);
	rs_key_free(key);
	return 4;
      }
    }
    else {
      infilename = "(standard input)";
      infile = stdin;
    }

    prgm = rs_program_new();

    if (ctype && dtype) {
      prgm->calctype = ctype;
      prgm->datatype = dtype;
    }
    else if ((ptr = strrchr(infilename, '.'))) {
      rs_suffix_to_type(ptr + 1, &prgm->calctype, &prgm->datatype);
    }

    if (rs_read_program_file(prgm, infile, infilename, flags)) {
      rs_program_free(prgm);
      rs_key_free(key);
      if (infile != stdin)
	fclose(infile);
      return 4;
    }
    if (infile != stdin)
      fclose(infile);

    /* Read key file (if automatic) */

    if (!keyfilename && !keyid) {
      appkeyid = rs_program_get_key_id(prgm);
      if (!appkeyid) {
	fprintf(stderr, "%s: unable to determine key ID\n", infilename);
	rs_program_free(prgm);
	rs_key_free(key);
	return 3;
      }

      if (appkeyid != key->id) {
	if (rs_key_find_for_id(key, appkeyid, valmode)) {
	  rs_program_free(prgm);
	  rs_key_free(key);
	  return 3;
	}
      }
    }

    if (valmode) {
      /* Validate application */
      if (verbose > 0)
	fprintf(stderr, "Validating %s %s %s...\n",
		rs_calc_type_to_string(prgm->calctype),
		rs_data_type_to_string(prgm->datatype),
		infilename);

      if (rs_validate_program(prgm, key))
	invalidapps++;
    }
    else {
      /* Sign application */
      if (verbose > 0)
	fprintf(stderr, "Signing %s %s %s...\n",
		rs_calc_type_to_string(prgm->calctype),
		rs_data_type_to_string(prgm->datatype),
		infilename);

      if (!rawmode) {
	if ((e = rs_repair_program(prgm, flags))) {
	  if (!(flags & RS_IGNORE_ALL_WARNINGS)
	      && e < RS_ERR_CRITICAL)
	    fprintf(stderr, "(use -f to override)\n");
	  rs_program_free(prgm);
	  rs_key_free(key);
	  return 2;
	}
      }
      if (rs_sign_program(prgm, key, rootnum)) {
	rs_program_free(prgm);
	rs_key_free(key);
	return 2;
      }

      /* Generate output file name */

      if (outfilename) {
	if (strcmp(outfilename, "-")) {
	  outfile = fopen(outfilename, "wb");
	  if (!outfile) {
	    perror(outfilename);
	    rs_program_free(prgm);
	    rs_key_free(key);
	    return 4;
	  }
	}
	else {
	  outfile = stdout;
	}
      }
      else if (infile == stdin) {
	outfile = stdout;
      }
      else {
	ext = rs_type_to_suffix(prgm->calctype, prgm->datatype,
				(flags & RS_OUTPUT_HEX_ONLY));

	tempname = rs_malloc(strlen(infilename) + 32);
	if (!tempname) {
	  rs_program_free(prgm);
	  rs_key_free(key);
	  return 4;
	}
	strcpy(tempname, infilename);

	ptr = strrchr(tempname, '.');
	if (!ptr) {
	  strcat(tempname, ".");
	  strcat(tempname, ext);
	}
	else if (strcasecmp(ptr + 1, ext)) {
	  strcpy(ptr + 1, ext);
	}
	else {
	  strcpy(ptr, "-signed.");
	  strcat(ptr, ext);
	}

	outfile = fopen(tempname, "wb");
	if (!outfile) {
	  perror(tempname);
	  rs_free(tempname);
	  rs_program_free(prgm);
	  rs_key_free(key);
	  return 4;
	}
	rs_free(tempname);
      }

      /* Write signed application to output file */

      if (rs_write_program_file(prgm, outfile, 0, 0, 0, flags)) {
	if (outfile != stdout)
	  fclose(outfile);
	rs_program_free(prgm);
	rs_key_free(key);
	return 4;
      }

      if (outfile != stdout)
	fclose(outfile);
    }
    rs_program_free(prgm);
  }

  rs_key_free(key);

  if (invalidapps)
    return 1;
  else
    return 0;
}
