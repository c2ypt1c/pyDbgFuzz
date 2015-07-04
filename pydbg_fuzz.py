from pydbg import *
from pydbg.defines import *

# obtained from the paimei project: https://github.com/OpenRCE/paimei/blob/master/utils/crash_binning.py
from crash_binning import *

import threading
import multiprocessing
import subprocess
import time

crash_dir = "C:\\crashdir\\"
gflags_path = "C:\\Program Files\\Windows Kits\\8.1\\Debuggers\\x86\\gflags.exe"

class pydbg_fuzz:
    def __init__(self, target_exe, fuzz_file=None, timeout=1):
        self.target_exe = target_exe
        self.fuzz_file = fuzz_file

        self.exe = target_exe[target_exe.rfind("\\")+1:]

        # ensure that no existing processes are initially running
        self.kill_proc()

        self.t = threading.Thread(target=self.fuzz)
        self.t.start()
        self.timer = threading.Timer(timeout, self.kill_proc)
        self.timer.start()

        # wait until thread terminates
        self.t.join()
    
    def close_fault_win(self):
        tasklist = subprocess.check_output("tasklist")

        fault_win = "WerFault.exe"
        if fault_win in tasklist:
            subprocess.call("taskkill /t /f /im %s" % fault_win)

    def kill_proc(self):
        self.close_fault_win()
        subprocess.call("taskkill /t /f /im %s" % self.exe, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def kill_python(self):
        subprocess.call("taskkill /t /f /im python.exe")

    def create_backup(self, timestamp):
            fin = open(self.fuzz_file, 'rb')
            fout = open("%s%s_poc.bak" % (crash_dir, timestamp), 'wb')
            fout.write(fin.read())
            fin.close()
            fout.close()

    def av_handler(self, dbg):
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED

        # cancel process termination timer
        self.timer.cancel()

        print "[!] ACCESS VIOLATION"

        timestamp = time.strftime("%m%d_%H-%M-%S", time.localtime())
        self.create_backup(timestamp)

        crash_bin = crash_binning()
        crash_bin.record_crash(dbg)

        f = open("%s%s_dbg.txt" % (crash_dir, timestamp), 'w')
        f.write(crash_bin.crash_synopsis())
        f.close()

        # manually terminate process
        self.kill_proc()

    def fuzz(self):
        self.dbg = pydbg()
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.av_handler)
        self.dbg.load(self.target_exe, self.fuzz_file)
        self.dbg.run()

# public funtions
def enable_gflags(exe):
    cmd = "%s /p /enable %s /full" % (gflags_path, exe)
    subprocess.call(cmd)

def disable_gflags(exe):
    cmd = "%s /p /disable %s /full" % (gflags_path, exe)
    subprocess.call(cmd)
