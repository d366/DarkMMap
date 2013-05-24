#!/usr/bin/env python

# This script will convert all TABs to SPACEs in the AsmJit root directory
# and all sub-directories (recursive).
#
# Converted sequences:
#   - The \r\n sequence is converted to \n (To UNIX line-ending).
#   - The \t (TAB) sequence is converted to TAB_REPLACEMENT which should
#     be two spaces.
#
# Affected files:
#   - *.cmake
#   - *.cpp
#   - *.h

import os

TAB_REPLACEMENT = "  "

for root, dirs, files in os.walk("../"):
  for f in files:
    if f.lower().endswith(".cpp") or f.lower().endswith(".h") or f.lower().endswith(".cmake") or f.lower().endswith(".txt"):
      path = os.path.join(root, f)

      fh = open(path, "rb")
      data = fh.read()
      fh.close()

      fixed = False

      if "\r" in data:
        print "Fixing \\r\\n in: " + path
        data = data.replace("\r", "")
        fixed = True

      if "\t" in data:
        print "Fixing TABs in: " + path
        data = data.replace("\t", TAB_REPLACEMENT)
        fixed = True

      if fixed:
        fh = open(path, "wb")
        fh.truncate()
        fh.write(data)
        fh.close()
