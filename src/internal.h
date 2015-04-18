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

#ifndef __RABBITSIGN_INTERNAL_H__
#define __RABBITSIGN_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

/**** Memory management (mem.c) ****/

#define rs_malloc(nnn) rs_realloc(0, (nnn))
#define rs_free(ppp) rs_realloc((ppp), 0)
void* rs_realloc (void* ptr, unsigned long count) RS_ATTR_MALLOC;
char* rs_strdup (const char* str) RS_ATTR_MALLOC;


/**** Rabin signature functions (rabin.c) ****/

/* Compute a Rabin signature and the useful value of f. */
RSStatus rs_sign_rabin (mpz_t res, int* f, const mpz_t hash,
			int rootnum, RSKey* key);

/* Check that the given Rabin signature is valid. */
RSStatus rs_validate_rabin (const mpz_t sig, int f, const mpz_t hash,
			    const RSKey* key);


/**** RSA signature functions (rsa.c) ****/

/* Compute an RSA signature. */
RSStatus rs_sign_rsa (mpz_t res, const mpz_t hash, RSKey* key);

/* Check that the given RSA signature is valid. */
RSStatus rs_validate_rsa (const mpz_t sig, const mpz_t hash,
			  const RSKey* key);


/**** TIFL file output (graphlink.c) ****/

/* Write TIFL header to a file. */
RSStatus rs_write_tifl_header (FILE* f, int is_hex, int major, int minor,
			       int month, int day, int year,
			       const char* name, int calctype, int datatype,
			       unsigned long filesize);


/**** Type <-> string conversions (typestr.c) ****/

/* Get default file suffix for a given calc/data type. */
const char* rs_type_to_suffix (RSCalcType calctype, RSDataType datatype,
			       int hexonly);

/* Get implied calc/data type for a given file suffix. */
int rs_suffix_to_type (const char* suff, RSCalcType* calctype,
		       RSDataType* datatype);

/* Get a human-readable description of a calculator type. */
const char* rs_calc_type_to_string (RSCalcType calctype);

/* Get a human-readable description of a data type. */
const char* rs_data_type_to_string (RSDataType datatype);


/**** Command line option parsing (cmdline.c) ****/

#define RS_CMDLINE_FINISHED 0
#define RS_CMDLINE_FILENAME '#'
#define RS_CMDLINE_HELP '!'
#define RS_CMDLINE_VERSION '@'
#define RS_CMDLINE_ERROR '?'

int rs_parse_cmdline(int argc, char** argv, const char* optstring,
		     int* i, int* j, const char** arg);


/**** Error/message logging (error.c) ****/

/* Display an error message */
void rs_error (const RSKey* key, const RSProgram* prgm,
	       const char* fmt, ...) RS_ATTR_PRINTF(3,4);

/* Display a warning message */
void rs_warning (const RSKey* key, const RSProgram* prgm,
		 const char* fmt, ...) RS_ATTR_PRINTF(3,4);

/* Display an informational message */
void rs_message (int level, const RSKey* key, const RSProgram* prgm,
		 const char* fmt, ...) /*RS_ATTR_PRINTF(4,5)*/;

#ifdef __cplusplus
}
#endif

#endif /* __RABBITSIGN_INTERNAL_H__ */
