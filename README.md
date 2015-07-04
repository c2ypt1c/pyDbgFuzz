# pydbg_fuzz
A simple pydbg wrapper to assit windows based fuzzing.

Example:
```python
from pydbg_fuzz import *

exe = "C:\\path_to_exe"
file = "C:\\path_to_file"
timeout = 1.0

enable_gflags(exe)

# main fuzzing loop
while(1):
    # do fuzzing operations
    # ...
    #

    fuzzer = pydbg_fuzz(exe, file)
    fuzzer.kill_proc(timeout)

disable_gflags(exe)

```
