import time
import psutil
from datetime import datetime

USB_ROOT = "/Volumes"

class ProcessMonitor:
    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.running = True

    def start(self):
        while self.running:
            for p in psutil.process_iter(['pid', 'exe', 'cmdline']):
                try:
                    exe = p.info.get('exe')
                    if exe and exe.startswith(USB_ROOT):
                        self.event_queue.put((
                            "LOG",
                            {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "level": "CRITICAL",
                                "message": "Runtime execution from USB detected",
                                "file_path": exe,
                                "extra": {
                                    "pid": p.pid,
                                    "source": "process_monitor"
                                }
                            }
                        ))
                except Exception:
                    pass
            time.sleep(1)

    def stop(self):
        self.running = False
