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
#ifndef _RUSAGE_KB_
#define _RUSAGE_KB_

/* As of 2017, most kernels' getrusage(2) returns ru_maxrss in kilobytes:
      Linux, Hurd, Free/Open/Net-BSD, MINIX, AIX7

   OpenSolaris's getrusage(2) documents a return value in pages,
   but it also says:
      "ru_maxrss, ru_ixrss, ru_idrss, and ru_isrss [...]
       are set to 0 in this implementation"

   GETRUSAGE_RETURNS_KB is set in configure.ac .
*/

#if GETRUSAGE_RETURNS_KB

/* define as no-op, as RUSAGE values are already in KB */
#define RUSAGE_MEM_TO_KB(x) (x)

#elif GETRUSAGE_RETURNS_BYTES

/* Convert bytes to kilobytes */
#define RUSAGE_MEM_TO_KB(x) ((x)/1024)

#elif GETRUSAGE_RETURNS_PAGES

/* Convert bytes to kilobytes */
#define RUSAGE_MEM_TO_KB(x) (ptok (x))

/* A function to get the system's page size and convert pages to KB */
unsigned long
ptok (unsigned long pages);

#else

#error "configuration error: no GETRUSAGE_RETURNS_{KB,BYTES,PAGES} defined"

#endif


/* Accessor functions.

   These also convert the value to uintmax_t, alleviating the need to
   worry about the type of ru->ru_maxrss (e.g. long, unsigned long,
   long long, etc),
   and on 64-bit systems 'uintmax_t' will be 64bit, reducing the need
   to worry about overflow in case of very large memory sizes. */
static inline uintmax_t
get_rusage_maxrss_kb (const struct rusage *ru)
{
  return (uintmax_t)RUSAGE_MEM_TO_KB (ru->ru_maxrss);
}

static inline uintmax_t
get_rusage_ixrss_kb (const struct rusage *ru)
{
  return (uintmax_t)RUSAGE_MEM_TO_KB (ru->ru_ixrss);
}

static inline uintmax_t
get_rusage_idrss_kb (const struct rusage *ru)
{
  return (uintmax_t)RUSAGE_MEM_TO_KB (ru->ru_idrss);
}

static inline uintmax_t
get_rusage_isrss_kb (const struct rusage *ru)
{
  return (uintmax_t)RUSAGE_MEM_TO_KB (ru->ru_isrss);
}

#endif /* _RUSAGE_KB_ */
