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
 * Check/fix program header and data.
 */
int rs_repair_program(RSProgram* prgm,	  /* app to repair */
		      unsigned int flags) /* flags */
{
  if (rs_calc_is_ti8x(prgm->calctype)) {
    if (prgm->datatype == RS_DATA_OS)
      return rs_repair_ti8x_os(prgm, flags);
    else if (prgm->datatype == RS_DATA_APP)
      return rs_repair_ti8x_app(prgm, flags);
  }

  if (rs_calc_is_ti9x(prgm->calctype)) {
    if (prgm->datatype == RS_DATA_OS)
      return rs_repair_ti9x_os(prgm, flags);
    else if (prgm->datatype == RS_DATA_APP)
      return rs_repair_ti9x_app(prgm, flags);
  }

  rs_error(NULL, prgm, "calc/data type (%X/%X) unrecognized",
	   prgm->calctype, prgm->datatype);
  return RS_ERR_UNKNOWN_PROGRAM_TYPE;
}

/*
 * Add a signature to the program.
 */
int rs_sign_program(RSProgram* prgm, /* app to sign */
		    RSKey* key,      /* signing key */
		    int rootnum)     /* signature number */
{
  if (rs_calc_is_ti8x(prgm->calctype)) {
    if (prgm->datatype == RS_DATA_OS)
      return rs_sign_ti8x_os(prgm, key);
    else if (prgm->datatype == RS_DATA_APP)
      return rs_sign_ti8x_app(prgm, key, rootnum);
  }

  return rs_sign_ti9x_app(prgm, key);
}

/*
 * Validate program signature.
 */
int rs_validate_program(const RSProgram* prgm, /* app to validate */
			const RSKey* key)      /* signing key */
{
  if (rs_calc_is_ti8x(prgm->calctype)) {
    if (prgm->datatype == RS_DATA_OS)
      return rs_validate_ti8x_os(prgm, key);
    else if (prgm->datatype == RS_DATA_APP)
      return rs_validate_ti8x_app(prgm, key);
  }

  return rs_validate_ti9x_app(prgm, key);
}

