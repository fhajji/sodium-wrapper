#!/bin/sh
# reformat.sh -- reformat files before committing.

FORMAT_BIN=/usr/local/bin/clang-format60

${FORMAT_BIN} -style="{BasedOnStyle: mozilla, IndentWidth: 4}" -i *.h *.cpp 
