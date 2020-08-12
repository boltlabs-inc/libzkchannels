#!/bin/sh

# Make sure all of these programs work properly
# when invoked with --help or --version.

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

# This test script was heavily copied from GNU sed's "help-version.sh"

. "${test_dir=.}/init.sh"

# VERSION should be set in Makefile.am
test "$VERSION" \
  || framework_failure_ "envvar VERSION is missing/empty"


# Ensure that it matches $VERSION.
v=$(env time --version | sed -n -e '1s/.* //p' -e 'q')
test "x$v" = "x$VERSION" \
  || fail_ "--version-\$VERSION mismatch"


# Make sure it exits successfully, under normal conditions.
env time --help    >/dev/null || fail=1
env time --version >/dev/null || fail=1

# TODO:
# Make sure it fails upon 'disk full' error
# (by adding atexit() call to clean-up STDOUT)

exit $fail
