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

/*
 * Write program contents to a file.
 */
int rs_write_program_file(const RSProgram* prgm, FILE* f,
			  int month, int day, int year,
			  unsigned int flags)
{
  if (rs_calc_is_ti8x(prgm->calctype)
      && (prgm->datatype == RS_DATA_OS || prgm->datatype == RS_DATA_APP))
    return rs_write_ti8x_file(prgm, f, month, day, year, flags);
  else
    return rs_write_ti9x_file(prgm, f, month, day, year, flags);
}
