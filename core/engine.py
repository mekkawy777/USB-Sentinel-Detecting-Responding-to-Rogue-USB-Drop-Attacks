import os
import time
import threading
import queue
import shutil

from core.usb import list_usb_drives
from core.ml import ml_score
from core.virustotal import vt_check
from core.process_monitor import ProcessMonitor


# ======================
# Configuration
# ======================
SAFE_VIEW_DIR = "safe_view"
QUARANTINE_DIR = "quarantine"

ML_SAFE = 0.4
ML_SUSPICIOUS = 0.7
VT_MALICIOUS_THRESHOLD = 10

EXECUTABLE_EXTS = [".exe", ".ps1", ".sh", ".bat", ".js"]

os.makedirs(SAFE_VIEW_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)


class UsbSentinelCore:
    def __init__(self, event_queue: queue.Queue, popup_callback):
        self._running = False
        self._event_queue = event_queue
        self._popup = popup_callback

        self.total_events = 0
        self.total_scanned_files = 0
        self.total_detected = 0
        self.total_quarantined = 0
        self.critical_count = 0
        self.last_usb = "N/A"

        self._seen_files = set()

    # =========================
    # Logging
    # =========================
    def log(self, level, msg, path=None, extra=None):
        self.total_events += 1
        self._event_queue.put((
            "LOG",
            {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "level": level,
                "message": msg,
                "file_path": path,
                "extra": extra or {}
            }
        ))

    def popup(self, msg):
        if self._popup:
            self._popup(msg)

    # =========================
    # SAFE VIEW (TEXT ONLY)
    # =========================
    def convert_to_safe_view(self, path):
        try:
            name = os.path.basename(path)
            safe_path = os.path.join(
                SAFE_VIEW_DIR,
                f"{name}.safe.txt"
            )

            with open(path, "rb") as src:
                data = src.read()

            with open(safe_path, "wb") as dst:
                dst.write(data)

            try:
                os.chmod(safe_path, 0o444)
            except Exception:
                pass

            return safe_path
        except Exception:
            return None

    # =========================
    # Quarantine
    # =========================
    def quarantine_file(self, path):
        try:
            name = os.path.basename(path)
            dst = os.path.join(
                QUARANTINE_DIR,
                f"{int(time.time())}_{name}"
            )
            shutil.move(path, dst)
            self.total_quarantined += 1
            return dst
        except Exception:
            return None

    # =========================
    # Delete original file
    # =========================
    def delete_original_file(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
        except Exception:
            pass
        return False

    # =========================
    # File Scan Pipeline
    # =========================
    def scan_file(self, path):
        self.total_scanned_files += 1

        # 1️⃣ Scan started
        self.log("INFO", "Scanning file", path)

        # 2️⃣ ML scoring
        score = ml_score(path)
        self.log(
            "INFO",
            "ML score calculated",
            path,
            extra={"ml_score": round(score, 2)}
        )

        ext = os.path.splitext(path)[1].lower()
        force_vt = ext in EXECUTABLE_EXTS

        # 3️⃣ SAFE
        if score < ML_SAFE and not force_vt:
            self.log(
                "INFO",
                "File classified SAFE by ML",
                path,
                extra={"ml_score": round(score, 2)}
            )
            self.log("INFO", "File scan completed", path)
            return

        self.total_detected += 1

        # 4️⃣ Suspicious → SAFE VIEW + DELETE
        if score < ML_SUSPICIOUS and not force_vt:
            safe_copy = self.convert_to_safe_view(path)
            self.delete_original_file(path)

            self.log(
                "WARNING",
                "Suspicious file analyzed → ORIGINAL DELETED (SAFE VIEW kept)",
                safe_copy,
                extra={"ml_score": round(score, 2)}
            )
            self.log("INFO", "File scan completed", safe_copy)
            return

        # 5️⃣ High Risk → VirusTotal
        self.critical_count += 1
        self.log(
            "WARNING",
            "High-risk file → submitting to VirusTotal",
            path,
            extra={"ml_score": round(score, 2)}
        )

        vt = vt_check(path)

        if vt:
            self.log(
                "INFO",
                "VirusTotal result received",
                path,
                extra=vt
            )

        # 6️⃣ Confirmed MALICIOUS → QUARANTINE + DELETE
        if vt and vt.get("malicious", 0) >= VT_MALICIOUS_THRESHOLD:
            qpath = self.quarantine_file(path)
            self.delete_original_file(path)

            self.log(
                "CRITICAL",
                "VirusTotal CONFIRMED malicious → QUARANTINE",
                qpath,
                extra={
                    "ml_score": round(score, 2),
                    "vt_malicious": vt.get("malicious")
                }
            )
            self.popup(
                f"🚨 MALICIOUS FILE BLOCKED\n\n"
                f"ML: {score:.2f}\n"
                f"VT detections: {vt.get('malicious')}"
            )

        else:
            safe_copy = self.convert_to_safe_view(path)
            self.delete_original_file(path)

            self.log(
                "WARNING",
                "High-risk file NOT confirmed → ORIGINAL DELETED (SAFE VIEW kept)",
                safe_copy,
                extra={
                    "ml_score": round(score, 2),
                    "vt_malicious": vt.get("malicious") if vt else None
                }
            )

        # 7️⃣ Scan completed
        self.log("INFO", "File scan completed", path)

    # =========================
    # Scan USB
    # =========================
    def scan_usb(self, root):
        for r, _, files in os.walk(root):
            for f in files:
                full = os.path.join(r, f)

                if "/." in full or "System Volume Information" in full:
                    continue

                if full not in self._seen_files:
                    self._seen_files.add(full)
                    self.scan_file(full)

    # =========================
    # Process Monitor Callback
    # =========================
    def on_usb_process_detected(self, exe, pid):
        self.log(
            "CRITICAL",
            f"USB process execution BLOCKED (PID {pid})",
            exe
        )
        self.popup(f"🚫 EXECUTION BLOCKED\n\n{exe}")

    # =========================
    # Monitor Loop
    # =========================
    def monitor_loop(self):
        self.log("INFO", "USB Sentinel engine started")

        while self._running:
            for d in list_usb_drives():
                if d != self.last_usb:
                    self.last_usb = d
                    self._seen_files.clear()
                    self.log("INFO", f"USB detected: {d}")

                self.scan_usb(d)

            self._event_queue.put(("STATS", None))
            time.sleep(1)

    # =========================
    # Control
    # =========================
    def start(self):
        if self._running:
            return

        self._running = True

        threading.Thread(
            target=self.monitor_loop,
            daemon=True
        ).start()

        self.proc_monitor = ProcessMonitor(
            list_usb_drives(),
            self.on_usb_process_detected
        )
        threading.Thread(
            target=self.proc_monitor.run,
            daemon=True
        ).start()

    def stop(self):
        self._running = False

    # =========================
    # Stats
    # =========================
    def get_stats(self):
        return {
            "total_events": self.total_events,
            "total_scanned": self.total_scanned_files,
            "total_detected": self.total_detected,
            "total_quarantined": self.total_quarantined,
            "critical_count": self.critical_count,
            "last_usb": self.last_usb,
        }
