# DifferenceURL
Library which shows the difference between several links

### The help message should explain the rest:

usage: url.py [-h] [-v] [--hostname] [--names] [--decode] [--quiet]
              [--case_insensitive]
              <left URL> [<right URL>]

It shows the difference between the two references

positional arguments:
  <left URL>            URL to diff against. Logically handled as the left
                        argument of diff.
  <right URL>           URL to diff against. Logically handled as the right
                        argument of diff.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --hostname            also diff URL hostname
  --names, -n           only diff URL parameter names.
  --decode, -d          URL decode parameter names and values (if applicable).
                        Decoded params will be used for comparison and
                        printing.
  --quiet, -q           suppress output and return non-zero if URLs differ.
  --case_insensitive, -i
                        Perform case insensitive diff. NOTE: this converts all
                        input to lowercase.

This is a small library that throws everything after the # sign
https://github.com/SteeinSource/DifferenceURL
