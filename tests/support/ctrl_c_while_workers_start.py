#!/usr/bin/env python3
"""Start a pool of workers while Ctrl-C reaches this process group every few milliseconds, and print
what the work returned."""
import os
import signal
import threading
import time

from stayawake.utils import parallel


def ctrl_c_mid_launch() -> None:
    """Send Ctrl-C to this process in the middle of starting each worker, and print what stopped."""
    from multiprocessing import popen_spawn_posix
    launch = popen_spawn_posix.Popen._launch

    def launch_after_ctrl_c(self, process_obj):
        os.kill(os.getpid(), signal.SIGINT)
        return launch(self, process_obj)

    popen_spawn_posix.Popen._launch = launch_after_ctrl_c
    try:
        parallel.run_ordered(abs, range(-64, 0), jobs=8)
    except KeyboardInterrupt:
        print("stopped")


def main() -> None:
    """Run the work under the Ctrl-C barrage and print its total."""
    signal.signal(signal.SIGINT, lambda *_: None)
    stop = threading.Event()

    def barrage() -> None:
        while not stop.is_set():
            os.killpg(0, signal.SIGINT)
            time.sleep(0.002)

    threading.Thread(target=barrage, daemon=True).start()
    outcomes = parallel.run_ordered(abs, range(-64, 0), jobs=8)
    stop.set()
    print(sum(outcome.value for outcome in outcomes))


if __name__ == "__main__":
    import sys

    ctrl_c_mid_launch() if sys.argv[1:] == ["mid-launch"] else main()
