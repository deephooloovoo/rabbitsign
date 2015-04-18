/*
 * Generate a random key file
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
 */

/*
 * NOTE: This program does not generate secure keys by default.  You
 * should use the --secure option if you actually want to use the key
 * for anything important.
 *
 * Secure key generation uses /dev/random, so it will only work on
 * systems which provide /dev/random, such as recent versions of
 * Linux, *BSD, Mac OS X, and Solaris.
 *
 * The security is thus obviously dependent on the implementation of
 * /dev/random.  Use at your own risk, as always.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <time.h>

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

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#else
# define getpid() 0
#endif

#include <gmp.h>

#define RANDOM_FILE "/dev/random"

void printnum(n)
     const mpz_t n;
{
  unsigned char buffer[1024];
  size_t size, i;

  mpz_export(buffer, &size, -1, 1, 0, 0, n);

  printf("%04X", (int)(size&0xffff));
  for (i=0; i<size; i++)
    printf("%02X", buffer[i]);

  putchar('\n');
}

void mprand(res, secure, nbits, rng)
     mpz_t res;
     int secure;
     unsigned int nbits;
     gmp_randstate_t rng;
{
  FILE *krandom;
  unsigned char buffer[1024];

  if (secure) {
    krandom = fopen(RANDOM_FILE, "rb");
    if (!krandom) {
      perror(RANDOM_FILE);
      exit(2);
    }

    if (fread(buffer, 1, (nbits+7)/8, krandom) < (nbits+7)/8) {
      if (feof(krandom)) {
	fprintf(stderr,"unexpected EOF while reading %s\n",
		RANDOM_FILE);
      }
      else {
	perror(RANDOM_FILE);
      }
      fclose(krandom);
      exit(2);
    }
    fclose(krandom);

    mpz_import(res, (nbits+7)/8, -1, 1, 0, 0, buffer);
  }
  else {
    mpz_urandomb(res, rng, nbits);
  }
}

int main(argc, argv)
     int argc;
     char **argv;
{
  mpz_t p, q, n;
  gmp_randstate_t rng;
  int ti_key = 0;
  int secure = 0;
  unsigned int length = 64;
  int pm8, qm8, pm17, qm17;
  int i;
  int e=17;
  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "--ti"))
      ti_key = 1;
    else if (0 == strcmp(argv[i], "--secure"))
      secure = 1;
    else if (0 == strcmp(argv[i], "--length") && i + 1 < argc
	     && sscanf(argv[i + 1], "%u", &length))
      i++;
    else if (0 == strcmp(argv[i], "--exponent") && i + 1 < argc
	     && sscanf(argv[i + 1], "%u", &e))
      i++;
    else {
      fprintf(stderr,"usage: %s [--secure] [--ti] [--length NBYTES] [--exponent e]\n",argv[0]);
      return 1;
    }
  }

  mpz_init(p);
  mpz_init(q);
  mpz_init(n);

  gmp_randinit_default(rng);
  gmp_randseed_ui(rng, time(NULL) + (100 * getpid()));

  if (secure)
    fprintf(stderr,"Generating a random key.  This may take a while.\n");

  /* Criteria for a usable signing key:

    - To use the key for Rabin signing, p and q must be different mod
      8, and neither can be 1 mod 8.  (TI's tools require that p === 3
      and q === 7.)  This is required so that, for any x, one of x,
      -x, 2x, and -2x is a square mod pq.

    - To use the key for RSA signing, (p - 1) and (q - 1) must be
      relatively prime to 17.  This is required so that every x has a
      17th root mod pq.
  */

  do {
    mprand(p, secure, length*4, rng);
    do {
      mpz_nextprime(p, p);
      pm8 = mpz_fdiv_ui(p, 8);
      pm17 = mpz_fdiv_ui(p, e);
    }
    while (pm17 == 1 || (ti_key ? (pm8 != 3) : (pm8 == 1)));

    mprand(q, secure, length*4, rng);
    do {
      mpz_nextprime(q, q);
      qm8 = mpz_fdiv_ui(q, 8);
      qm17 = mpz_fdiv_ui(q, e);
    }
    while (qm17 == 1 || (ti_key ? (qm8 != 7) : (qm8 == pm8 || qm8 == 1)));

    mpz_mul(n, p, q);

  } while (mpz_sizeinbase(n, 16) > length*2);

  printnum(n); 
  printf("01%02X\n",e);
  printnum(p);
  printnum(q);

  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(n);

  return 0;
}
