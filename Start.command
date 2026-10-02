#!/bin/zsh
cd -- "${0:A:h}" || exit 1
/usr/bin/python3 launcher.py start
result=$?
if (( result != 0 )); then
  printf '\nPress Return to close.\n'
  read -r reply
fi
exit "$result"
