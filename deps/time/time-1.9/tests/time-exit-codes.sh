#!/bin/sh

# Test exit codes

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

# Ensure time propagates the correct exit codes,
# and reports them in the output file.
# TODO: exit codes > 127 in a portable way?
for i in 0 1 3 5 100 123 125 126 128 ;
do
    printf "%d\n" "$i" > exp$i || framework_failure_
    returns_ $i \
             env time -q -o out$i -f "%x" \
                  time-aux -e "$i" || fail=1
    compare exp$i out$i || fail=1
done

exit $fail
