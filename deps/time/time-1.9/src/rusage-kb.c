/* resuse.h - declarations for child process resource use library
   Copyright (C) 2017-2018 Free Software Foundation, Inc.

   This file is part of GNU Time.

   GNU Time is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   GNU Time is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Time.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#if GETRUSAGE_RETURNS_PAGES

#include <sys/types.h>
#include <limits.h>
#include <unistd.h>

/* Return the number of kilobytes corresponding to a number of pages PAGES.
   (Actually, we use it to convert pages*ticks into kilobytes*ticks.)

   Try to do arithmetic so that the risk of overflow errors is minimized.
   This is funky since the pagesize could be less than 1K.
   Note: Some machines express getrusage statistics in terms of K,
   others in terms of pages.  */
unsigned long
ptok (unsigned long pages)
{
  static unsigned long ps = 0;
  unsigned long tmp;
  static long size = LONG_MAX;

  /* Initialization.  */
  if (ps == 0)
    ps = (long) getpagesize ();

  /* Conversion.  */
  if (pages > (LONG_MAX / ps))
    {
      /* Could overflow. */
      tmp = pages / 1024;  /* Smaller first, */
      size = tmp * ps;     /* then larger.  */
    }
  else
    {
      /* Could underflow. */
      tmp = pages * ps;     /* Larger first, */
      size = tmp / 1024;    /* then smaller.  */
    }
  return size;
}

#endif /* !GETRUSAGE_RETURNS_PAGES */
