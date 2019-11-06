#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

/* 1 second = 1E9 nanoseconds */
#define NS_1E9 1000000000

enum {
  EXIT_CANCELED = 125
};

static void
errx (int eval, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end(ap);
  fputc ( '\n', stderr);
  exit (eval);
}

static int
get_exit_code (const char* num)
{
  long int l = 0;
  char *pch = NULL ;

  errno = 0;
  l = strtol (optarg, &pch, 10);
  if (errno != 0 || l < 0 || l > 255 || pch == optarg || *pch != '\0' )
    errx (EXIT_CANCELED, "invalid exit code '%s'", optarg);

  return (int)l;
}


static void
do_malloc (const char* optarg)
{
  long int l = 0, i = 0, multiplier = 1 ;
  void *p = NULL ;
  char* pch = NULL;

  errno = 0;
  l = strtol (optarg, &pch, 10);
  if (errno != 0 || pch == optarg || l <= 0 )
    errx (EXIT_CANCELED, "invalid malloc request '%s'", optarg);

  /* Optional multiplier */
  switch (*pch)
    {
    case 'b':
    case 'B':
      multiplier = 1;
      pch++;
      break;

    case 'k':
    case 'K':
      multiplier = 1024;
      pch++;
      break;
    case 'm':
    case 'M':
      multiplier = 1024 * 1024 ;
      pch++;
      break;
    case 'g':
    case 'G':
      multiplier = 1024 * 1024 * 1024 ;
      pch++;
      break;
    case '\0':
      break;
    }
  if (*pch != '\0')
    errx (EXIT_CANCELED, "invalid malloc request '%s' " \
          "(multiplier error)", optarg);

  l = l * multiplier ;
  if ( l < 1 || l > 1024 * 1024 * 1024 )
    errx (EXIT_CANCELED, "invalid malloc request '%s' " \
          "(size too large/small)", optarg);

  p = malloc (l);
  if (p==NULL)
    errx (EXIT_FAILURE, "malloc failed (%ld bytes), errno=%d", l, errno);

  /* access the memory to ensure it is resident, not virtual */
  pch = (char*)p;
  for (i = 0; i < l ; i += 1000, pch += 1000)
    *pch = 4;
}

static void
parse_timespec (const char* s, struct timespec /*out*/ *ts)
{
  long int sleep_s = 0, sleep_ns = 0, l = 0;
  char* pch = NULL;

  errno = 0;
  l = strtol (s, &pch, 10);
  if (errno != 0 || pch == s || l <= 0 )
    errx (EXIT_CANCELED, "invalid time '%s'", s);

  /* Optional multiplier */
  switch (*pch)
    {
    case 'n': /* nanoseconds */
      sleep_ns = l;
      ++pch;
      if (*pch == 's')
	++pch;
      break;

    case 'u': /* microseconds */

      /* prevent signed overflow */
      if (l >(LONG_MAX/1000))
	errx (EXIT_CANCELED, "invalid time '%s' " \
	      "(value too high for microseconds/u units", s);

      sleep_ns = l * 1000 ;
      ++pch;
      if (*pch == 's')
	++pch;
      break;

    case 's': /* seconds */
      sleep_s = l;
      ++pch;
      break;

    case 'm': /* minutes */
    case 'M':
      sleep_s = l * 60 ;
      ++pch;
      break;

    case '\0':
      errx (EXIT_CANCELED, "missing time unit for value '%s' (ns/us/s/m)",
	    optarg, s);
      break;

    default:
      errx (EXIT_CANCELED, "invalid time unit '%c' for time '%s' ",
	    *pch, s);
    }
  if (*pch != '\0')
    errx (EXIT_CANCELED, "invalid time '%s' (unit error)", s);

  /* Normalize nano-seconds/seconds */
  if (sleep_ns >= NS_1E9)
    {
      sleep_s = sleep_ns / NS_1E9;
      sleep_ns = sleep_ns % NS_1E9;
    }

  if (
      ((sleep_s<=0) && (sleep_ns<=0))
      ||
      (sleep_s > 24 * 60 * 60 )
      )
    errx (EXIT_CANCELED, "invalid time '%s' " \
          "(too large/small)", optarg);

  ts->tv_sec = sleep_s;
  ts->tv_nsec = sleep_ns;
}

static void
busy_user_sleep (const struct timespec *sleep)
{
  struct timespec start, cur;
  long int diff_s, diff_ns;
  long int sleep_s = sleep->tv_sec;
  long int sleep_ns = sleep->tv_nsec;

  if (clock_gettime (CLOCK_MONOTONIC, &start)!=0)
    errx (EXIT_FAILURE, "clock_gettime failed, errno=%d", errno);

  while (1) {
    if (clock_gettime (CLOCK_MONOTONIC, &cur)!=0)
      errx (EXIT_FAILURE, "clock_gettime failed, errno=%d", errno);

    diff_s = cur.tv_sec - start.tv_sec;
    diff_ns = cur.tv_nsec - start.tv_nsec;

    if (diff_ns < 0) {
      --diff_s ;
      diff_ns += 1E9;
    }

    if ((diff_s >= sleep_s) && (diff_ns >= sleep_ns))
      break;

    /* waste some cycles */
    diff_s = diff_ns % 100;
  }
}

static void
busy_sys_sleep (const struct timespec *sleep)
{
  struct timespec start, cur;
  long int diff_s, diff_ns;
  long int sleep_s = sleep->tv_sec;
  long int sleep_ns = sleep->tv_nsec;
  pid_t pid,ppid;
  uid_t uid,euid;
  gid_t gid,egid;
  char buf[100];

  if (clock_gettime (CLOCK_MONOTONIC, &start)!=0)
    errx (EXIT_FAILURE, "clock_gettime failed, errno=%d", errno);

  while (1) {
    if (clock_gettime (CLOCK_MONOTONIC, &cur)!=0)
      errx (EXIT_FAILURE, "clock_gettime failed, errno=%d", errno);

    diff_s = cur.tv_sec - start.tv_sec;
    diff_ns = cur.tv_nsec - start.tv_nsec;

    if (diff_ns < 0) {
      --diff_s ;
      diff_ns += 1E9;
    }

    if ((diff_s >= sleep_s) && (diff_ns >= sleep_ns))
      break;

    /* waste some cycles in the kernel using system calls */
    pid = getpid();
    ppid = getppid();
    uid = getuid();
    euid = geteuid();
    gid = getgid();
    egid = getegid();
    getcwd (buf, 10 + (pid+ppid+uid+euid+gid+egid)&0xF);
  }
}

static void
safe_nanosleep (const struct timespec *ts)
{
  int i;
  struct timespec req,rem;
  req = *ts;
  while (1)
    {
      errno = 0 ;
      i = nanosleep (&req, &rem);
      if (i==0)
	break;
      else if (i==-1 && errno == EINTR)
	req = rem;
      else
	errx (EXIT_FAILURE, "nanosleep failed, errno=%d", errno);
    }
}


static void
do_busy_user_sleep (const char* optarg)
{
  struct timespec ts;

  parse_timespec (optarg, &ts);
  busy_user_sleep (&ts);
}

static void
do_busy_sys_sleep (const char* optarg)
{
  struct timespec ts;

  parse_timespec (optarg, &ts);
  busy_sys_sleep (&ts);
}

static void
do_sleep (const char* optarg)
{
  struct timespec ts;

  parse_timespec (optarg, &ts);
  safe_nanosleep (&ts);
}

static void
do_half_busy_sleep (const char* optarg)
{
  const unsigned int iters = 4 ;
  struct timespec ts, ts2;

  parse_timespec (optarg, &ts);

  ts2.tv_sec = ts.tv_sec / iters ;
  ts2.tv_nsec = ts.tv_nsec / iters +
    ( ( ts.tv_sec % iters ) * NS_1E9 ) / iters ;

  for (int i=0; i<iters/2 ; ++i)
    {
      busy_user_sleep (&ts2);
      safe_nanosleep (&ts2);
    }
}


static void
usage (void)
{
  puts("Usage: time-aux [OPTIONS]\n\
Wastes time and memory to test GNU time\n\
\n\
OPTIONS\n\
 -b TIME   waste TIME in a CPU busy loop (consuming 'user' time)\n\
 -e N      terminate with exit code N (default: 0)\n\
 -h        this help screen\n\
 -H TIME   waste/sleep TIME (half in busy loop, half in sleep)\n\
 -k TIME   waste TIME in kernel syscalls (approx.)\n\
 -m SIZE   allocate SIZE bytes memory (accepts K/M/G suffix)\n\
 -s TIME   sleep TIME without wasting CPU time\n\
\n\
TIME must have a suffix:\n\
m (minutes), s (seconds), us (microseconds), ns (nanoseconds)\n\
\n\
Example:\n\
Allocate 200 MBs, sleep for 1 second, then busy-loop for 1 second,\n\
then terminate with exit code 4:\n\
  time-aux -m 200M -s 1s -b 1s -e 4\n\
\n\
");
  exit(0);
}

int main (int argc, char *argv[])
{
  int c;
  int rc = 0 ;

  while ( (c = getopt(argc,argv,"e:m:b:s:H:k:h")) != -1 )
    {
      switch (c)
        {
        case 'e': /* Set exit code */
          rc = get_exit_code (optarg);
          break;

        case 'm': /* Malloc */
          do_malloc (optarg);
          break;

	case 'h':
	  usage();
	  break;

        case 'b': /* busy loop, waste CPU cycles for X seconds*/
          do_busy_user_sleep (optarg);
          break;

        case 's': /* sleep without wasting CPU cycles in user mode */
          do_sleep (optarg);
          break;

        case 'H': /* half busy loop, half sleep */
          do_half_busy_sleep (optarg);
          break;

        case 'k': /* busy loop, wasting kernel/system time */
          do_busy_sys_sleep (optarg);
          break;

        default:
          errx (EXIT_CANCELED,"invalid option");
        }
    }

  return rc;
}
