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
 * Get default file suffix for a given calc/data type.
 */
const char* rs_type_to_suffix(RSCalcType calctype, /* calculator type */
			      RSDataType datatype, /* program data type */
			      int hexonly)	   /* 1 = plain hex output */
{
  if (calctype == RS_CALC_TI73) {
    if (datatype == RS_DATA_APP)
      return (hexonly ? "app" : "73k");
    else if (datatype == RS_DATA_OS)
      return (hexonly ? "hex" : "73u");
    else if (datatype == RS_DATA_CERT)
      return "73q";
  }
  else if (calctype == RS_CALC_TI83P) {
    if (datatype == RS_DATA_APP)
      return (hexonly ? "app" : "8xk");
    else if (datatype == RS_DATA_OS)
      return (hexonly ? "hex" : "8xu");
    else if (datatype == RS_DATA_CERT)
      return "8xq";
  }
  else if (calctype == RS_CALC_TI89) {
    if (datatype == RS_DATA_APP)
      return "89k";
    else if (datatype == RS_DATA_OS)
      return "89u";
    else if (datatype == RS_DATA_CERT)
      return "89q";
  }
  else if (calctype == RS_CALC_TI92P) {
    if (datatype == RS_DATA_APP)
      return "9xk";
    else if (datatype == RS_DATA_OS)
      return "9xu";
    else if (datatype == RS_DATA_CERT)
      return "9xq";
  }

  return "sig";
}

/*
 * Get implied calc/data type for a given file suffix.
 */
int rs_suffix_to_type(const char* suff,     /* file suffix (not
					       including .) */
		      RSCalcType* calctype, /* implied calculator
					       type */
		      RSDataType* datatype) /* implied program type */
{
  int calc, data;

  if (strlen(suff) != 3)
    return -1;

  if (suff[0] == '7' && suff[1] == '3')
    calc = RS_CALC_TI73;
  else if (suff[0] == '8' && (suff[1] == 'x' || suff[1] == 'X'))
    calc = RS_CALC_TI83P;
  else if (suff[0] == '8' && suff[1] == '9')
    calc = RS_CALC_TI89;
  else if (suff[0] == '9' && (suff[1] == 'x' || suff[1] == 'X'))
    calc = RS_CALC_TI92P;
  else if ((suff[0] == 'v' || suff[0] == 'V') && suff[1] == '2')
    calc = RS_CALC_TI92P;
  else
    return -1;

  if (suff[2] == 'k' || suff[2] == 'K')
    data = RS_DATA_APP;
  else if (suff[2] == 'u' || suff[2] == 'U')
    data = RS_DATA_OS;
  else if (suff[2] == 'q' || suff[2] == 'Q')
    data = RS_DATA_CERT;
  else
    return -1;

  if (calctype) *calctype = calc;
  if (datatype) *datatype = data;
  return 0;
}

/*
 * Get a human-readable description of a calculator type.
 */
const char* rs_calc_type_to_string(RSCalcType calctype)
{
  switch (calctype) {
  case RS_CALC_TI73:
    return "TI-73";

  case RS_CALC_TI83P:
    return "TI-83/84 Plus";

  case RS_CALC_TI89:
    return "TI-89";

  case RS_CALC_TI92P:
    return "TI-92 Plus/Voyage 200";

  default:
    return "unknown";
  }
}

/*
 * Get a human-readable description of a data type.
 */
const char* rs_data_type_to_string(RSDataType datatype)
{
  switch (datatype) {
  case RS_DATA_OS:
    return "OS";

  case RS_DATA_APP:
    return "application";

  case RS_DATA_CERT:
    return "certificate";

  default:
    return "program";
  }
}
