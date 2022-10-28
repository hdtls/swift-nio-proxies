#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the Netbot open source project
##
## Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
## Licensed under Apache License v2.0
##
## See LICENSE for license information
## See CONTRIBUTORS.txt for the list of Netbot project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu
here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
(
  cd "$here/.."
  {
    find . \
      \( \! -path '**/.*' -a -name '*.gyb' \)
  } | while read file; do
    printf "Creating file: ${file%.gyb}\n"
    $here/gyb --line-directive '' -o "${file%.gyb}" "$file";
  done
)
