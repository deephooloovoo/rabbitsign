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

void* rs_realloc(void* ptr, unsigned long count)
{
  void* p;

  if (!count) {
    if (ptr) {
      free(ptr);
    }
    return NULL;
  }

  if (ptr)
    p = realloc(ptr, count);
  else
    p = malloc(count);
  if (!p)
    rs_error(NULL, NULL, "out of memory (need %lu bytes)", count);
  return p;
}

char* rs_strdup(const char* str)
{
  int n;
  char* p;

  if (!str)
    return NULL;

  n = strlen(str);
  p = rs_malloc(n + 1);
  if (p)
    memcpy(p, str, n + 1);
  return p;  
}
