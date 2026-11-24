#!/usr/bin/env python3
"""Start a pool of workers while Ctrl-C reaches this process group every few milliseconds, and print
what the work returned."""
import os
import signal
import threading
import time

from stayawake.utils import parallel


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
    main()
