🛡️ USB Sentinel

Advanced USB Threat Detection & Security Dashboard

USB Sentinel is a professional-grade USB security monitoring platform designed to detect, analyze, and contain threats delivered through removable media.
The system is fully dashboard-driven and integrates behavioral analysis, machine learning, YARA rules, cryptography, and SIEM-style logging.



🔥 Core Capabilities

 Real-time USB device detection
 Advanced malware analysis pipeline
 Machine Learning–based threat classification
 YARA rules engine for signature detection
 Process behavior monitoring
 Encrypted quarantine system
 Secure file inspection (Safe View)
 Centralized SIEM-style event logging
 Qt-based Security Operations Dashboard



🖥️ Dashboard-Driven Architecture

USB Sentinel operates exclusively through a graphical security dashboard.
No command-line interaction is required during normal operation.



🧠 Detection Pipeline

1. USB device insertion detected
2. File metadata & entropy analysis
3. YARA signature scanning
4. Machine learning classification
5. Runtime process behavior analysis
6. Threat scoring & decision engine
7. Encrypted quarantine or safe release
8. Event correlation & logging



🗂️ Project Structure

```
USB_Sentinel/
├── gui/
│   └── dashboard_qt.py        # Main SOC dashboard
├── core/
│   ├── central.py             # System orchestrator
│   ├── engine.py              # Threat detection engine
│   ├── usb.py                 # USB monitoring
│   ├── ml.py                  # Machine learning analysis
│   ├── yara_rules.py          # YARA scanning
│   ├── process_monitor.py     # Behavioral analysis
│   ├── virustotal.py          # External reputation checks
│   ├── crypto.py              # Encryption & secure handling
│   └── siem.py                # SIEM-style logging
├── tools/                     # Utility tools
├── quarantine/                # Encrypted isolated storage
├── safe_view/                 # Secure file viewing sandbox
├── logs/                      # System logs
├── sentinel_log.json          # Central security log
└── sentinel.key               # Cryptographic key
```



⚙️ Requirements

 Python 3.8+
 Qt Framework (PyQt / PySide)
 YARA
 Optional: Internet access for reputation services



🚀 Installation

```
git clone https://github.com/USERNAME/USB_Sentinel.git
cd USB_Sentinel
pip install -r requirements.txt
```



▶️ Launch Dashboard

```
python gui/dashboard_qt.py
```



🔐 Security Principles

 Zero Trust for removable media
 No direct execution from USB
 Encrypted quarantine by default
 Analyst interaction only via dashboard
 Full event traceability



🎯 Target Use Cases

 SOC & Blue Team operations
 Malware analysis labs
 Endpoint security research
 Academic cyber security projects



📈 Future Enhancements

 EDR integration
 Cloud-based threat intelligence
 USB device fingerprinting
 Policy-based enforcement



🤝 Contributing

Security researchers and developers are welcome to contribute via pull requests.



📄 License

MIT License
