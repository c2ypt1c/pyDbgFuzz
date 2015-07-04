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

    pydbg_fuzz(exe, file, timeout)

disable_gflags(exe)

```
