### Description
Simple command line tool to update resource strings in widnows executables.


Sample usage:
rc_string.exe program.exe [id value]*
  Where id is string ID and value is the new string value.
  Multiple pairs of id/value can be specified. Example:
  rc_string.exe program.exe 100 "new value" 101 "example.com"
