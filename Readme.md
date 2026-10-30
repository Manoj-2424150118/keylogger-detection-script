# 🛡️ Keylogger Detection Script

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()
[![GitHub Issues](https://img.shields.io/github/issues/Manoj-2424150118/keylogger-detection-script.svg)](https://github.com/Manoj-2424150118/keylogger-detection-script/issues)

A comprehensive Python script for detecting potential keylogger threats on your system. This tool performs multi-layered scanning to identify suspicious processes, files, registry entries, network connections, and system hooks that may indicate keylogger activity.

## 🚀 Features

- **Single File Solution**: Everything in one Python script - no complex installation
- **Multi-Layer Scanning**: 
  - Running processes analysis
  - File system suspicious pattern detection
  - Registry entry monitoring (Windows)
  - Network connection analysis
  - System hooks detection
- **Detailed JSON Reports**: Comprehensive scan results with timestamps
- **Windows-only**: Built for Windows — registry and system-hook checks use Windows APIs, and the script exits on other platforms
- **Admin Privilege Support**: Enhanced scanning with elevated permissions
- **Real-time Progress**: Visual feedback during scanning process

## 📋 Sample Output
Keylogger Detection Script
This tool will scan your system for potential keylogger threats.
Note: This requires administrator privileges for full functionality.
Starting keylogger detection scan...
This may take a few minutes...
Checking running processes...
Checking for suspicious files...
Checking registry entries...
Checking network connections...
Checking for system hooks...
============================================================
KEYLOGGER DETECTION REPORT
Scan completed at: 2025-07-03T15:06:12.933717
Summary:

Suspicious processes: 0
Suspicious files: 6796
Suspicious registry entries: 0
Suspicious network connections: 0
Hooks detected: 0

SUSPICIOUS FILES:

Path: C:\Users\XYZ\Keylogger_detection_script.py
Size: 16824 bytes
Modified: 2025-07-03T14:57:30.218745
Reason: Suspicious filename pattern

============================================================
ASSESSMENT: High risk - many suspicious items detected!
Report saved to: keylogger_scan_20250703_150613.json
Scan completed successfully!
Review the findings above and take appropriate action if threats are detected.

## 🔧 Installation & Usage

### Quick Start

1. **Download the script**
   ```bash
   git clone https://github.com/Manoj-2424150118/keylogger-detection-script.git
   cd keylogger-detection-script

Install dependencies
bashpip install -r requirements.txt

Run the script
bash# Basic usage
python Keylogger_Detection_Script.py

# With administrator privileges (recommended)
# Run as Administrator on Windows


Alternative Installation
Direct download and run:
bash# Download just the main script
wget https://raw.githubusercontent.com/Manoj-2424150118/keylogger-detection-script/main/Keylogger_Detection_Script.py

# Install dependencies
pip install psutil pywin32

# Run
python Keylogger_Detection_Script.py
📊 What the Script Detects
Suspicious Processes

Processes with keylogger-related names
Hidden or suspicious system processes
Processes with unusual network activity

Suspicious Files

Files with keylogger-related patterns in names
Executable files in unusual locations
Recently modified system files
Files with suspicious extensions

Registry Entries (Windows)

Startup entries pointing to suspicious files
Registry keys commonly used by keyloggers
Modified system registry entries

Network Connections

Unusual outbound connections
Connections to suspicious domains
Processes with unexpected network activity

System Hooks

Keyboard hooks
Mouse hooks
Window message hooks

🔍 Understanding the Results
Risk Assessment Levels

Low Risk: 0-10 suspicious items detected
Medium Risk: 11-100 suspicious items detected
High Risk: 100+ suspicious items detected

Common False Positives

Development Tools: IDEs, debuggers, and development software
System Files: Legitimate system files with suspicious-sounding names
Antivirus Software: Security tools that use similar techniques
Remote Access Tools: Legitimate remote desktop software

Report Files
The script generates detailed JSON reports in the format:

keylogger_scan_YYYYMMDD_HHMMSS.json
Contains complete scan results with timestamps and file details

⚠️ Important Notes
Security Disclaimer

This tool is for legitimate security purposes only
Use only on systems you own or have explicit permission to scan
Not intended for malicious use or unauthorized system access

System Requirements

Python 3.6 or higher
Administrator/root privileges (recommended for full functionality)
Internet connection (for some network-based checks)

Limitations

May produce false positives with legitimate software
Cannot detect all types of keyloggers (especially advanced ones)
Effectiveness depends on system privileges and access rights

🛠️ Dependencies
The script requires these Python packages:

psutil - System and process monitoring
pywin32 - Windows API access (win32api, win32con, win32process, win32security; Windows only)
winreg - Windows registry access (standard library, Windows only)

Everything else the script uses (os, sys, hashlib, time, json, datetime, pathlib) is Python standard library - no other packages are required.

📝 Troubleshooting
Common Issues
Permission Denied Errors:
bash# Run with elevated privileges
# Right-click and "Run as Administrator" on Windows
Missing Dependencies:
bash# Install all required packages
pip install psutil pywin32
High False Positive Rate:

Review the suspicious files list carefully
Check if flagged items are legitimate system files
Consider your system's specific software configuration

Scan Takes Too Long:

The script may take several minutes on systems with many files
Progress is shown during the scan
Consider running during off-peak hours

Platform-Specific Notes
Windows:

Registry scanning requires administrator privileges
Some system files may be protected and inaccessible
Windows Defender may flag the script (false positive)

Other platforms:

The script is Windows-only and exits on non-Windows systems (see `main()` in `Keylogger_detection_script.py`) — there is no Linux/macOS mode, and registry scanning is not "skipped", the script does not run there at all.

🤝 Contributing
Found a bug or want to improve the script?

Report Issues: Use the GitHub issues page
Suggest Features: Open a feature request
Submit Improvements: Fork and create a pull request

Development Guidelines

Keep the single-file architecture
Keep the Windows-only scope (the script exits on non-Windows systems)
Add comments for complex logic
Test on Windows

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgments

Built with Python for Windows system inspection
Inspired by cybersecurity best practices
Thanks to the open-source community for tools and libraries

📞 Support

Issues: GitHub Issues
Discussions: GitHub Discussions
Email: sharmamanojkumar697@gmail.com


⚠️ Disclaimer: This tool is provided "as is" for educational and legitimate security purposes. Users are responsible for compliance with local laws and regulations.
⭐ Star this repository if you find it helpful!

---

## requirements.txt

> A ready-to-use `requirements.txt` is included in this repo — install with
> `pip install -r requirements.txt`. It lists the runtime dependencies the
> script actually imports (`psutil`, plus `pywin32` on Windows). The block
> below mirrors it. Older versions of this README also listed `requests`,
> `python-dateutil` and `colorama` - the script does not import them, so they
> have been removed.

```txt
# Core dependencies for keylogger detection
psutil>=5.6.0

# Windows-specific (required on Windows)
pywin32>=223; sys_platform == "win32"

```
