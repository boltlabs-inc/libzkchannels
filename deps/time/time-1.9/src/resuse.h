/* resuse.h - declarations for child process resource use library
   Copyright (C) 1993-2018 Free Software Foundation, Inc.

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

#ifndef _RESUSE_H
#define _RESUSE_H 1


/* Convert rusage's microseconds to miliseconds */
#define TV_MSEC tv_usec / 1000



/* Information on the resources used by a child process.  */
typedef struct
{
  int waitstatus;
  struct rusage ru;
  struct timeval start, elapsed; /* Wallclock time of process.  */
} RESUSE;

/* Prepare to measure a child process.  */
void resuse_start (RESUSE *resp);

/* Wait for and fill in data on child process PID.  */
int resuse_end (pid_t pid, RESUSE *resp);

#endif /* _RESUSE_H */
