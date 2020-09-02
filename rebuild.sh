#!/bin/bash

cd deps/emp-tool
make local
cd ../emp-ag2pc
make local
cd ../..
make release
