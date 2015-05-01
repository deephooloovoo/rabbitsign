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

#ifndef __RABBITSIGN_H__
#define __RABBITSIGN_H__

#ifdef HAVE_GMP_H
# include <gmp.h>
# define rs_snprintf gmp_snprintf
# define rs_vsnprintf gmp_vsnprintf
#else
# include "mpz.h"
#endif

#if __GNUC__ >= 3
# define RS_ATTR_PURE __attribute__((pure))
# define RS_ATTR_MALLOC __attribute__((malloc))
# define RS_ATTR_UNUSED __attribute__((unused))
# define RS_ATTR_PRINTF(f,i) __attribute__((format(printf,f,i)))
#else
# define RS_ATTR_PURE
# define RS_ATTR_MALLOC
# define RS_ATTR_UNUSED
# define RS_ATTR_PRINTF(f,i)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Calculator types */
typedef enum _RSCalcType {
  RS_CALC_UNKNOWN = 0,
  RS_CALC_TI73    = 0x74,
  RS_CALC_TI83P   = 0x73,
  RS_CALC_TI89    = 0x98,
  RS_CALC_TI92P   = 0x88
} RSCalcType;

#define rs_calc_is_ti8x(ttt) ((ttt) == RS_CALC_TI73 || (ttt) == RS_CALC_TI83P)
#define rs_calc_is_ti9x(ttt) ((ttt) == RS_CALC_TI89 || (ttt) == RS_CALC_TI92P)

/* Data types */
typedef enum _RSDataType {
  RS_DATA_UNKNOWN = 0,
  RS_DATA_OS      = 0x23,
  RS_DATA_APP     = 0x24,
  RS_DATA_CERT    = 0x25
} RSDataType;

/* Flags for app signing */
typedef enum _RSRepairFlags {
  RS_IGNORE_ALL_WARNINGS     = 1,
  RS_REMOVE_OLD_SIGNATURE    = 2, /* Remove existing signature */
  RS_FIX_PAGE_COUNT          = 4, /* Fix page count header field */
  RS_FIX_OS_SIZE             = 8, /* Fix size in OS header */
  RS_ZEALOUSLY_PAD_APP       = 16 /* Pad application with an extra
                                     page if necessary */
} RSRepairFlags;

/* Flags for file input */
typedef enum _RSInputFlags {
  RS_INPUT_BINARY            = 32, /* Assume input is raw binary
                                      data */
  RS_INPUT_SORTED            = 64  /* Assume plain hex input is sorted
                                      (implicit page switch) */
} RSInputFlags;

/* Flags for file output */
typedef enum _RSOutputFlags {
  RS_OUTPUT_HEX_ONLY         = 128, /* Write plain hex (.app) format */
  RS_OUTPUT_APPSIGN          = 256, /* Write hex data in
                                       appsign-compatible format */
  RS_OUTPUT_BINARY           = 512  /* Write binary data for CE */
} RSOutputFlags;
typedef enum _RSKeyType {
  RS_KEY_MD5 = 0,
  RS_KEY_SHA256 = 1
} RSKeyType;
/* Encryption key structure */
typedef struct _RSKey {
  char* filename;               /* Filename */
  unsigned long id;             /* Key ID */
  mpz_t n;                      /* Modulus (public key) */
  mpz_t p;                      /* First factor */
  mpz_t q;                      /* Second factor */
  mpz_t e;
  mpz_t qinv;                   /* q^-1 mod p (for Rabin)
                                   (rs_sign_rabin() will calculate
                                   this based on p and q, if
                                   needed) */
  mpz_t d;                      /* Signing exponent (for RSA)
                                   (rs_sign_rsa() will calculate this
                                   based on p and q, if needed) */
} RSKey;

/* Program data structure */
typedef struct _RSProgram {
  char* filename;                /* Filename */
  RSCalcType calctype;           /* Calculator type */
  RSDataType datatype;           /* Program data type */
  RSKeyType keytype;
  unsigned char* data;           /* Program data */
  unsigned long length;          /* Length of program data */
  unsigned long length_a;        /* Size of buffer allocated */

  /* Additional metadata (only used by TI-8x OS) */
  unsigned char version;         /* OS header version */
  unsigned char* header;         /* OS header */
  unsigned int header_length;    /* Length of OS header */
  unsigned char* signature;      /* OS signature */
  unsigned int signature_length; /* Length of OS signature */
  unsigned int* pagenums;        /* List of page numbers */
  int npagenums;                 /* Number of page numbers */
} RSProgram;

/* Status codes */
typedef enum _RSStatus {
  RS_SUCCESS = 0,

  RS_ERR_MISSING_PAGE_COUNT,
  RS_ERR_MISSING_KEY_ID,
  RS_ERR_MISSING_DATE_STAMP,
  RS_ERR_MISSING_PROGRAM_IMAGE,
  RS_ERR_MISALIGNED_PROGRAM_IMAGE,
  RS_ERR_INVALID_PROGRAM_DATA,
  RS_ERR_INVALID_PROGRAM_SIZE,
  RS_ERR_INCORRECT_PAGE_COUNT,
  RS_ERR_FINAL_PAGE_TOO_LONG,
  RS_ERR_FIELD_TOO_SMALL,

  RS_ERR_CRITICAL = 1000,

  RS_ERR_OUT_OF_MEMORY,
  RS_ERR_FILE_IO,
  RS_ERR_HEX_SYNTAX,
  RS_ERR_UNKNOWN_FILE_FORMAT,
  RS_ERR_UNKNOWN_PROGRAM_TYPE,
  RS_ERR_MISSING_HEADER,
  RS_ERR_MISSING_RABIN_SIGNATURE,
  RS_ERR_MISSING_RSA_SIGNATURE,
  RS_ERR_INCORRECT_PROGRAM_SIZE,
  RS_ERR_KEY_NOT_FOUND,
  RS_ERR_KEY_SYNTAX,
  RS_ERR_INVALID_KEY,
  RS_ERR_MISSING_PUBLIC_KEY,
  RS_ERR_MISSING_PRIVATE_KEY,
  RS_ERR_UNSUITABLE_RABIN_KEY,
  RS_ERR_UNSUITABLE_RSA_KEY,

  RS_SIGNATURE_INCORRECT = -1
} RSStatus;


/**** Key handling (keys.c) ****/

/* Create a new key. */
RSKey* rs_key_new (void) RS_ATTR_MALLOC;

/* Free a key. */
void rs_key_free (RSKey* key);

/* Read key from a file. */
RSStatus rs_read_key_file (RSKey* key, FILE* f,
			   const char* fname, int verify);

/* Parse a number written in TI's hexadecimal key format. */
RSStatus rs_parse_key_value (mpz_t dest, const char* str);


/**** Program data manipulation (program.c) ****/

/* Create a new program. */
RSProgram* rs_program_new (void) RS_ATTR_MALLOC;

/* Create a new program from an existing data buffer. */
RSProgram* rs_program_new_with_data (RSCalcType ctype, RSDataType dtype,
				     void* data, unsigned long length,
				     unsigned long buffer_size)
  RS_ATTR_MALLOC;

/* Free program data. */
void rs_program_free (RSProgram* prgm);

/* Truncate or extend program. */
RSStatus rs_program_set_length (RSProgram* prgm, unsigned long length);

/* Add data to the end of the program. */
RSStatus rs_program_append_data (RSProgram* prgm, const unsigned char* data,
				 unsigned long length);


/**** Search for key file (autokey.c) ****/

/* Get key ID for the given program. */
unsigned long rs_program_get_key_id (const RSProgram* prgm) RS_ATTR_PURE;

/* Find key file for the given ID. */
RSStatus rs_key_find_for_id (RSKey* key, unsigned long keyid, int publiconly);


/**** Program signing and validation (apps.c) ****/

/* Check/fix program header and data. */
RSStatus rs_repair_program (RSProgram* prgm, RSRepairFlags flags);

/* Add a signature to the program. */
RSStatus rs_sign_program (RSProgram* prgm, RSKey* key, int rootnum);

/* Validate program signature. */
RSStatus rs_validate_program (const RSProgram* prgm, const RSKey* key);


/**** TI-73/83+/84+ app signing (app8x.c) ****/

/* Check/fix Flash app header and data. */
RSStatus rs_repair_ti8x_app (RSProgram* app, RSRepairFlags flags);

/* Add a signature to a Flash app. */
RSStatus rs_sign_ti8x_app (RSProgram* app, RSKey* key, int rootnum);

/* Validate Flash app signature. */
RSStatus rs_validate_ti8x_app (const RSProgram* app, const RSKey* key);


/**** TI-73/83+/84+ OS signing (os8x.c) ****/

/* Check/fix OS header and data. */
RSStatus rs_repair_ti8x_os (RSProgram* os, RSRepairFlags flags);

/* Add a signature to an OS. */
RSStatus rs_sign_ti8x_os (RSProgram* os, RSKey* key);

/* Validate OS signature. */
RSStatus rs_validate_ti8x_os (const RSProgram* os, const RSKey* key);


/**** TI-89/92+ app/OS signing (app9x.c) ****/

/* Check/fix Flash app header and data. */
RSStatus rs_repair_ti9x_app (RSProgram* app, RSRepairFlags flags);

/* Check/fix OS header and data. */
RSStatus rs_repair_ti9x_os (RSProgram* app, RSRepairFlags flags);

/* Add a signature to a 68k app/OS. */
RSStatus rs_sign_ti9x_app (RSProgram* app, RSKey* key);

/* Validate app/OS signature. */
RSStatus rs_validate_ti9x_app (const RSProgram* app, const RSKey* key);

#define rs_sign_ti9x_os rs_sign_ti9x_app
#define rs_validate_ti9x_os rs_validate_ti9x_app


/**** File input (input.c) ****/

/* Read program contents from a file. */
RSStatus rs_read_program_file (RSProgram* prgm, FILE* f,
			       const char* fname, RSInputFlags flags);


/**** File output (output.c) ****/

/* Write program contents to a file. */
RSStatus rs_write_program_file(const RSProgram* prgm, FILE* f,
			       int month, int day, int year,
			       RSOutputFlags flags);


/**** Hex file output (output8x.c) ****/

/* Write program to a .73k/.73u/.8xk/.8xu or .app file. */
RSStatus rs_write_ti8x_file (const RSProgram* prgm, FILE* f,
			     int month, int day, int year,
			     RSOutputFlags flags);


/**** Binary file output (output9x.c) ****/

/* Write program to a .89k/.89u/.9xk/.9xu file. */
RSStatus rs_write_ti9x_file (const RSProgram* prgm, FILE* f,
			     int month, int day, int year,
			     RSOutputFlags flags);


/**** App header/certificate utility functions (header.c) ****/

/* Get length of a header field. */
void rs_get_field_size (const unsigned char* data,
			unsigned long* fieldstart,
			unsigned long* fieldsize);

/* Set length of a header field. */
int rs_set_field_size (unsigned char* data,
		       unsigned long fieldsize);

/* Find a given header field in the data. */
int rs_find_app_field (unsigned int type,
		       const unsigned char* data,
		       unsigned long length,
		       unsigned long* fieldhead,
		       unsigned long* fieldstart,
		       unsigned long* fieldsize);

/* Get value of a numeric header field. */
unsigned long rs_get_numeric_field (unsigned int type,
				    const unsigned char* data,
				    unsigned long length) RS_ATTR_PURE;


/**** Error/message logging (error.c) ****/
  
typedef void (*RSMessageFunc) (const RSKey*, const RSProgram*,
			       const char*, void*);

/* Set program name */
void rs_set_progname (const char* s);

/* Set verbosity level */
void rs_set_verbose (int v);

/* Set error logging function */
void rs_set_error_func (RSMessageFunc func, void* data);

/* Set message logging function */
void rs_set_message_func (RSMessageFunc func, void* data);


#ifdef __cplusplus
}
#endif

#endif /* __RABBITSIGN_H__ */
