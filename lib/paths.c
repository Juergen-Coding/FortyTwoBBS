/* SPDX-License-Identifier: GPL-2.0-only */

/*
    Copyright (C) 2021 MBSE Development Team

    This file is part of MBSE BBS.

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "mbselib.h"

char *join_paths(const char *path_left, size_t left_len, const char *path_right, size_t right_len) {
  size_t result_bytes_max = left_len + right_len + 2;
  char *result;

  if (NULL == path_left || NULL == path_right || left_len <= 0 || right_len <= 0) {
    return NULL;
  }

  result = (char *)calloc(result_bytes_max, sizeof(char));
  if (result == NULL) {
    return NULL;
  }

  char *nullch = memccpy(result, path_left, '\0', left_len);
  size_t offset;
  if (NULL == nullch) {
    offset = left_len;
  } else {
    offset = nullch - result - 1;
  }

  result[offset++] = '/';

  nullch = memccpy(result + offset, path_right, '\0', right_len);
  if (NULL != nullch) {
     /* resize the output */
     char *tmp = (char *)realloc(result, nullch - result + 1);
     if (NULL == tmp) {
       return result; /* realloc failed, return original */
     }
     result = tmp;
  }

  return result;
}