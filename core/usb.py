import os
import platform

OS = platform.system()


def list_usb_drives():
    drives = set()

    # ===== macOS =====
    if OS == "Darwin":
        base = "/Volumes"
        try:
            for name in os.listdir(base):
                path = os.path.join(base, name)
                if os.path.ismount(path):
                    drives.add(path)
        except Exception:
            pass

    # ===== Linux =====
    elif OS == "Linux":
        for base in ("/media", "/mnt", "/run/media"):
            if os.path.isdir(base):
                for root, dirs, _ in os.walk(base):
                    for d in dirs:
                        path = os.path.join(root, d)
                        if os.path.ismount(path):
                            drives.add(path)

    # ===== Windows =====
    elif OS == "Windows":
        import win32file
        import win32con

        mask = win32file.GetLogicalDrives()
        for i in range(26):
            if mask & (1 << i):
                drive = f"{chr(65+i)}:\\"
                if win32file.GetDriveType(drive) == win32con.DRIVE_REMOVABLE:
                    drives.add(drive)

    return drives
