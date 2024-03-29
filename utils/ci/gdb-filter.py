def exit_handler (event):
    """
    Write exit code of the program running in gdb to a file called exit.out.txt
    """
    code = 1
    if hasattr(event, "exit_code"):
        code = event.exit_code
    with open("exit.out.txt", 'w') as f:
        f.write(f"{code}")

def gdb_execmany(*cmds):
    """
    Run multiple gdb commands
    """
    for cmd in cmds:
        gdb.execute(cmd)

def crash_handler (event):
    """
    Handle a crash from the program running in gdb
    """
    if isinstance(event, gdb.SignalEvent):
        log_file_name = "crash.out.txt"
        # poop out log file for stack trace of all threads
        gdb_execmany(f"set logging file {log_file_name}", "set logging enabled on", "set logging redirect on", "thread apply all bt full")
        # quit gdb
        gdb.execute("q")

# set up event handlers to catch crashes
gdb.events.stop.connect(crash_handler)
gdb.events.exited.connect(exit_handler)

# run settings setup
gdb_execmany("set confirm off", "set pagination off", "set print thread-events off")
# run program and exit
gdb_execmany("r", "q")
