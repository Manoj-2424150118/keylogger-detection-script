# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

#!/usr/bin/env python3
"""
Keylogger Detection Script
A comprehensive tool to detect potential keyloggers on Windows systems.
"""

import os
import sys
import psutil
import winreg
import hashlib
import time
import json
from datetime import datetime
from pathlib import Path
import win32api
import win32con
import win32process
import win32security

class KeyloggerDetector:
    def __init__(self):
        self.suspicious_processes = []
        self.suspicious_files = []
        self.suspicious_registry = []
        self.network_connections = []
        self.hooks_detected = []
        
        # Known keylogger signatures and patterns
        self.keylogger_signatures = {
            'process_names': [
                'keylogger', 'keycapture', 'keystroke', 'spyware',
                'revealer', 'actual spy', 'perfect keylogger', 'home keylogger',
                'invisible keylogger', 'advanced keylogger', 'elite keylogger'
            ],
            'file_extensions': ['.key', '.log', '.kbd', '.spy'],
            'registry_keys': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
            ],
            'suspicious_directories': [
                'temp', 'tmp', 'windows\\temp', 'appdata\\local\\temp'
            ]
        }
    
    def check_running_processes(self):
        """Check for suspicious processes that might be keyloggers"""
        print("Checking running processes...")
        
        for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pinfo = process.info
                process_name = pinfo['name'].lower() if pinfo['name'] else ''
                
                # Check against known keylogger process names
                for sus_name in self.keylogger_signatures['process_names']:
                    if sus_name in process_name:
                        self.suspicious_processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'exe': pinfo['exe'],
                            'reason': f'Suspicious process name: {sus_name}'
                        })
                
                # Check for processes with unusual characteristics
                if pinfo['exe']:
                    exe_path = Path(pinfo['exe'])
                    
                    # Check if process is running from suspicious locations
                    for sus_dir in self.keylogger_signatures['suspicious_directories']:
                        if sus_dir in str(exe_path).lower():
                            self.suspicious_processes.append({
                                'pid': pinfo['pid'],
                                'name': pinfo['name'],
                                'exe': pinfo['exe'],
                                'reason': f'Running from suspicious directory: {sus_dir}'
                            })
                
                # Check for processes with no window (hidden)
                if process_name and not any(window.strip() for window in process.cmdline() if window):
                    if self.is_process_hidden(pinfo['pid']):
                        self.suspicious_processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'exe': pinfo['exe'],
                            'reason': 'Hidden process with no visible window'
                        })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def is_process_hidden(self, pid):
        """Check if a process is running hidden"""
        try:
            # This is a simplified check - in practice, you'd need more sophisticated detection
            return False  # Placeholder for actual hidden process detection
        except Exception:
            return False
    
    def check_suspicious_files(self):
        """Check for suspicious files that might be keylogger logs"""
        print("Checking for suspicious files...")
        
        search_paths = [
            os.path.expanduser('~'),
            'C:\\Windows\\Temp',
            'C:\\Temp',
            os.path.expandvars('%APPDATA%'),
            os.path.expandvars('%LOCALAPPDATA%')
        ]
        
        for search_path in search_paths:
            if os.path.exists(search_path):
                try:
                    for root, dirs, files in os.walk(search_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            file_lower = file.lower()
                            
                            # Check file extensions
                            for ext in self.keylogger_signatures['file_extensions']:
                                if file_lower.endswith(ext):
                                    self.suspicious_files.append({
                                        'path': file_path,
                                        'reason': f'Suspicious file extension: {ext}',
                                        'size': self.get_file_size(file_path),
                                        'modified': self.get_file_modified_time(file_path)
                                    })
                            
                            # Check for files with keylogger-like names
                            keylogger_terms = ['key', 'log', 'capture', 'stroke', 'spy']
                            if any(term in file_lower for term in keylogger_terms):
                                if self.is_suspicious_log_file(file_path):
                                    self.suspicious_files.append({
                                        'path': file_path,
                                        'reason': 'Suspicious filename pattern',
                                        'size': self.get_file_size(file_path),
                                        'modified': self.get_file_modified_time(file_path)
                                    })
                except (PermissionError, OSError):
                    continue
    
    def is_suspicious_log_file(self, file_path):
        """Check if a file contains keylogger-like content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Read first 1KB
                
                # Look for patterns typical of keylogger logs
                suspicious_patterns = [
                    '[ENTER]', '[BACKSPACE]', '[TAB]', '[SHIFT]',
                    'password', 'login', 'username', 'keystroke'
                ]
                
                return any(pattern.lower() in content.lower() for pattern in suspicious_patterns)
        except Exception:
            return False
    
    def get_file_size(self, file_path):
        """Get file size safely"""
        try:
            return os.path.getsize(file_path)
        except OSError:
            return 0
    
    def get_file_modified_time(self, file_path):
        """Get file modification time safely"""
        try:
            return datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        except OSError:
            return "Unknown"
    
    def check_registry_entries(self):
        """Check Windows registry for suspicious entries"""
        print("Checking registry entries...")
        
        for reg_path in self.keylogger_signatures['registry_keys']:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        
                        # Check if the registry entry points to a suspicious executable
                        if isinstance(value, str):
                            value_lower = value.lower()
                            for sus_name in self.keylogger_signatures['process_names']:
                                if sus_name in value_lower:
                                    self.suspicious_registry.append({
                                        'key': reg_path,
                                        'name': name,
                                        'value': value,
                                        'reason': f'Suspicious registry value: {sus_name}'
                                    })
                        
                        i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                
            except WindowsError:
                continue
    
    def check_network_connections(self):
        """Check for suspicious network connections"""
        print("Checking network connections...")
        
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    process_name = process.name().lower()
                    
                    # Check if the process making network connections is suspicious
                    for sus_name in self.keylogger_signatures['process_names']:
                        if sus_name in process_name:
                            self.network_connections.append({
                                'pid': conn.pid,
                                'process': process.name(),
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                'status': conn.status,
                                'reason': 'Suspicious process with network connection'
                            })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    
    def check_system_hooks(self):
        """Check for system hooks that might be used by keyloggers"""
        print("Checking for system hooks...")
        
        # This is a simplified check - actual hook detection would require
        # more sophisticated Windows API calls
        try:
            # Placeholder for actual hook detection
            # In practice, you'd use Windows API functions like:
            # - SetWindowsHookEx detection
            # - GetWindowLong checks
            # - Process injection detection
            pass
        except Exception:
            pass
    
    def generate_report(self):
        """Generate a comprehensive report of findings"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'suspicious_processes': len(self.suspicious_processes),
                'suspicious_files': len(self.suspicious_files),
                'suspicious_registry': len(self.suspicious_registry),
                'suspicious_connections': len(self.network_connections),
                'hooks_detected': len(self.hooks_detected)
            },
            'findings': {
                'processes': self.suspicious_processes,
                'files': self.suspicious_files,
                'registry': self.suspicious_registry,
                'network': self.network_connections,
                'hooks': self.hooks_detected
            }
        }
        
        return report
    
    def print_report(self, report):
        """Print a formatted report to console"""
        print("\n" + "="*60)
        print("KEYLOGGER DETECTION REPORT")
        print("="*60)
        print(f"Scan completed at: {report['scan_time']}")
        print(f"Summary:")
        print(f"  - Suspicious processes: {report['summary']['suspicious_processes']}")
        print(f"  - Suspicious files: {report['summary']['suspicious_files']}")
        print(f"  - Suspicious registry entries: {report['summary']['suspicious_registry']}")
        print(f"  - Suspicious network connections: {report['summary']['suspicious_connections']}")
        print(f"  - Hooks detected: {report['summary']['hooks_detected']}")
        
        if report['findings']['processes']:
            print(f"\nSUSPICIOUS PROCESSES:")
            for process in report['findings']['processes']:
                print(f"  - PID: {process['pid']}, Name: {process['name']}")
                print(f"    Path: {process['exe']}")
                print(f"    Reason: {process['reason']}")
        
        if report['findings']['files']:
            print(f"\nSUSPICIOUS FILES:")
            for file in report['findings']['files']:
                print(f"  - Path: {file['path']}")
                print(f"    Size: {file['size']} bytes")
                print(f"    Modified: {file['modified']}")
                print(f"    Reason: {file['reason']}")
        
        if report['findings']['registry']:
            print(f"\nSUSPICIOUS REGISTRY ENTRIES:")
            for entry in report['findings']['registry']:
                print(f"  - Key: {entry['key']}")
                print(f"    Name: {entry['name']}")
                print(f"    Value: {entry['value']}")
                print(f"    Reason: {entry['reason']}")
        
        if report['findings']['network']:
            print(f"\nSUSPICIOUS NETWORK CONNECTIONS:")
            for conn in report['findings']['network']:
                print(f"  - Process: {conn['process']} (PID: {conn['pid']})")
                print(f"    Local: {conn['local_address']}")
                print(f"    Remote: {conn['remote_address']}")
                print(f"    Status: {conn['status']}")
                print(f"    Reason: {conn['reason']}")
        
        print("\n" + "="*60)
        
        # Risk assessment
        total_findings = sum(report['summary'].values())
        if total_findings == 0:
            print("ASSESSMENT: No obvious keylogger threats detected.")
        elif total_findings <= 2:
            print("ASSESSMENT: Low risk - few suspicious items found.")
        elif total_findings <= 5:
            print("ASSESSMENT: Medium risk - several suspicious items detected.")
        else:
            print("ASSESSMENT: High risk - many suspicious items detected!")
        
        print("="*60)
    
    def save_report(self, report, filename=None):
        """Save the report to a JSON file"""
        if filename is None:
            filename = f"keylogger_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Report saved to: {filename}")
    
    def run_scan(self):
        """Run the complete keylogger detection scan"""
        print("Starting keylogger detection scan...")
        print("This may take a few minutes...")
        
        try:
            self.check_running_processes()
            self.check_suspicious_files()
            self.check_registry_entries()
            self.check_network_connections()
            self.check_system_hooks()
            
            report = self.generate_report()
            self.print_report(report)
            self.save_report(report)
            
            return report
            
        except Exception as e:
            print(f"Error during scan: {e}")
            return None

def main():
    """Main function to run the keylogger detector"""
    if sys.platform != 'win32':
        print("This script is designed for Windows systems only.")
        sys.exit(1)
    
    print("Keylogger Detection Script")
    print("This tool will scan your system for potential keylogger threats.")
    print("Note: This requires administrator privileges for full functionality.")
    
    detector = KeyloggerDetector()
    report = detector.run_scan()
    
    if report:
        print("\nScan completed successfully!")
        print("Review the findings above and take appropriate action if threats are detected.")
    else:
        print("Scan failed. Please check permissions and try again.")

if __name__ == "__main__":
    main()