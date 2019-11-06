#!/bin/sh

# Test MAX-RSS (Resident size) reporting

# Copyright (C) 2017-2018 Free Software Foundation, Inc.
#
# This file is part of GNU Time.
#
# GNU Time is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# GNU Time is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU time.  If not, see <http://www.gnu.org/licenses/>.

# Written by Assaf Gordon
. "${test_dir=.}/init.sh"

fail=

# The auxiliary program should be built and runnable
time-aux || framework_failure_ "time-aux is missing/not runnable"

# Get the baseline number of MAX-RSS kilobytes
# use by the program when not allocating any extra memory
env time -o mem-baseline -f "%M" time-aux \
  || framework_failure_ "failed to run time/time-aux (baseline max-rss)"

# Allocate 5MB of RAM
env time -o mem-5MB -f "%M" time-aux -m 5M \
  || framework_failure_ "failed to run time/time-aux (5M max-rss)"

# Calculate the difference
b=$(cat mem-baseline) || framework_failure_ "failed to read mem-baseline"
c=$(cat mem-5MB) || framework_failure_ "failed to read mem-5MB"
d=$(( c - b ))

# On some systems (e.g. OpenSolaris) getrusage(2) returns zero in ru_maxrss.
# Detect and skip the test if this is the case.
test "$b" -eq "0" && test "$c" -eq 0 \
  && skip_ "getrusage(2) returns zero in ru_maxrss"

# There could be alot of variation between each invocation,
# accept a reasonable range
if test "$d" -ge 5000 && test "$d" -le 6000 ; then
    : # acceptable values: 5000-6000 KB
else
    cat<<EOF>&2
time(1) failed to detect 5MB allcoation.
  mem-baseline(kb): $b
  mem-5MB(kb):      $c
  delta(kb):        $d
EOF
    fail=1
fi


exit $fail
