import time
import queue
from core.engine import UsbSentinelCore

q = queue.Queue()
core = UsbSentinelCore(q, lambda _: None)
core.start()

while True:
    time.sleep(10)
