/* resuse.c - child process resource use library
   Copyright (C) 1993-2018 Free Software Foundation, Inc.

   Written by David MacKenzie, with help from
   arnej@imf.unit.no (Arne Henrik Juul)
   and pinard@iro.umontreal.ca (Francois Pinard).

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
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>

#if !HAVE_WAIT3
# include <sys/times.h>
# ifndef HZ
#  include <sys/param.h>
# endif
# if !defined(HZ) && defined(CLOCKS_PER_SEC)
#  define HZ CLOCKS_PER_SEC
# endif
# if !defined(HZ) && defined(CLK_TCK)
#  define HZ CLK_TCK
# endif
# ifndef HZ
#  define HZ 60
# endif
#endif

#include "resuse.h"

/* Prepare to measure a child process.  */

void
resuse_start (resp)
     RESUSE *resp;
{
#if HAVE_WAIT3
  gettimeofday (&resp->start, (struct timezone *) 0);
#else
  long value;
  struct tms tms;

  value = times (&tms);
  resp->start.tv_sec = value / HZ;
  resp->start.tv_usec = value % HZ * (1000000 / HZ);
#endif
}

/* Wait for and fill in data on child process PID.
   Return 0 on error, 1 if ok.  */

#if __STDC__
/* pid_t is short on BSDI, so don't try to promote it.  */
int
resuse_end (pid_t pid, RESUSE *resp)
#else
int
resuse_end (pid, resp)
     pid_t pid;
     RESUSE *resp;
#endif
{
  int status;

#if HAVE_WAIT3
  pid_t caught;

  /* Ignore signals, but don't ignore the children.  When wait3
     returns the child process, set the time the command finished. */
  while ((caught = wait3 (&status, 0, &resp->ru)) != pid)
    {
      if (caught == -1)
	return 0;
    }

  gettimeofday (&resp->elapsed, (struct timezone *) 0);
#else  /* !HAVE_WAIT3 */
  long value;
  struct tms tms;

  pid = wait (&status);
  if (pid == -1)
    return 0;

  value = times (&tms);

  memset (&resp->ru, 0, sizeof (struct rusage));

  resp->ru.ru_utime.tv_sec = tms.tms_cutime / HZ;
  resp->ru.ru_stime.tv_sec = tms.tms_cstime / HZ;

#if HAVE_SYS_RUSAGE_H
  resp->ru.ru_utime.tv_nsec = tms.tms_cutime % HZ * (1000000000 / HZ);
  resp->ru.ru_stime.tv_nsec = tms.tms_cstime % HZ * (1000000000 / HZ);
#else
  resp->ru.ru_utime.tv_usec = tms.tms_cutime % HZ * (1000000 / HZ);
  resp->ru.ru_stime.tv_usec = tms.tms_cstime % HZ * (1000000 / HZ);
#endif

  resp->elapsed.tv_sec = value / HZ;
  resp->elapsed.tv_usec = value % HZ * (1000000 / HZ);
#endif  /* !HAVE_WAIT3 */

  resp->elapsed.tv_sec -= resp->start.tv_sec;
  if (resp->elapsed.tv_usec < resp->start.tv_usec)
    {
      /* Manually carry a one from the seconds field.  */
      resp->elapsed.tv_usec += 1000000;
      --resp->elapsed.tv_sec;
    }
  resp->elapsed.tv_usec -= resp->start.tv_usec;

  resp->waitstatus = status;

  return 1;
}
