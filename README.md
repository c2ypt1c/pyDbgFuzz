# pydbg_fuzz

A simple pydbg wrapper to assit with windows based fuzzing

Example:

from pydbg_fuzz import *

exe = "C:\\path_to_exe"
file = "C:\\path_to_file"
timeout = 1.0

# main fuzz loop
while(1):
    # do fuzzing operations

    fuzzer = pydbg_fuzz(exe, file)
    fuzzer.kill_proc(timeout)

