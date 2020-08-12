#!/bin/sh

# Test output quietness with -q and -p

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

which false > /dev/null || skip_ "'false' program required for this test"
which sed > /dev/null || skip_ "'sed' program required for this test"

# Remove the actual values from a file (they'll differ every run).
remove_numeric_values()
{
    sed -e 's/[?0-9.]*//g' -e 's/ *$//' "$@"
}

fail=


##
## Default output
##
## Has extra "command exited with non-zero status" message

cat<<EOF > exp-default || framework_failure_ "failed to write exp-default"
Command exited with non-zero status
user system :elapsed %CPU (avgtext+avgdata maxresident)k
inputs+outputs (major+minor)pagefaults swaps
EOF

returns_ 1 env time -o out-def1 false || fail=1

remove_numeric_values out-def1 > out-default \
    || framework_failure_ "sed failed on out-def1"

compare_ out-default exp-default || fail=1




##
## -q output
##
## originally from Debian, "-q" supresses the "command exited..." message

cat<<EOF > exp-q  || framework_failure_ "failed to write exp-q"
user system :elapsed %CPU (avgtext+avgdata maxresident)k
inputs+outputs (major+minor)pagefaults swaps
EOF

returns_ 1 env time -q -o out-q1 false || fail=1

remove_numeric_values out-q1 > out-q \
    || framework_failure_ "sed failed on out-q"

compare_ out-q exp-q || fail=1


##
## -p (POSIX) output
##
## versions 1.8 and older add "Command exited with non-zero status" message.
cat<<EOF > exp-posix || framework_failure_ "failed to write exp-posix"
real
user
sys
EOF

returns_ 1 env time -p -o out-posix1 false || fail=1

remove_numeric_values out-posix1 > out-posix \
    || framework_failure_ "sed failed on out-posix1"

compare_ out-posix exp-posix || fail=1


exit $fail
