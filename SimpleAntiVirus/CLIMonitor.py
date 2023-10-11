import psutil
import time
import tkinter as tk
from plyer import notification
import os
import logging

# Configure logging
logging.basicConfig(filename='cli_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

class CLIMonitor:
    def __init__(self):
        self.active = True
        self.suspicious_keywords = ["Invoke-Expression", "Base64", "DownloadString", "/c", "dir", "Get-ChildItem"]
        self.suspicious_parameters = ["-NoProfile", "-WindowStyle Hidden"]
        self.contextual_indicators = ["C:\\Temp\\", "Desktop\\"]
        
    def start_monitoring(self):
        self.active = True
        self.notify("CLI Monitor Is now active")

    def stop_monitoring(self):
        self.active = False
        self.notify("CLI Monitor Is no longer active")

    def notify(self, message):
        notification.notify(
            title="CLI Monitor",
            message=message,
            app_name="SimpleAntivirus",
            timeout=3
        )

    def is_suspicious(self, cmdline):
        # Convert the command line to lowercase for case-insensitive matching
        cmdline_lower = cmdline.lower()

        # Scans in known malicious domains into array
        known_mal_domains = "scan_known_malware/malicious_domains.txt"
        with open(known_mal_domains, 'r') as file:
            malicious_domains = [line.strip() for line in file]

        # Suspicious keywords and phrases
        if any(keyword.lower() in cmdline_lower for keyword in self.suspicious_keywords):
            return True

        # Script block logging indicators
        if '{' in cmdline and '}' in cmdline:
            return True

        # Execution of unsigned scriptsp
        if "Set-ExecutionPolicy" in cmdline and "-Scope" in cmdline and "Unrestricted" not in cmdline:
            return True

        # Check for encoded commands (Base64 or other encoding)
        if "-encodedcommand" in cmdline_lower:
            return True

        # Detect attempts to hide the command with obfuscation techniques
        if any(indicator.lower() in cmdline_lower for indicator in ["iex", "invoke-expression"]):
            return True

        # Network activity (e.g., downloading from suspicious URLs)
        if "-uri" in cmdline_lower and any(domain.lower() in cmdline_lower for domain in malicious_domains):
            return True

        # Suspicious parameters or arguments
        if any(param.lower() in cmdline_lower for param in self.suspicious_parameters):
            return True

        # Contextual checks (e.g., execution from unusual locations)
        if any(indicator.lower() in cmdline_lower for indicator in self.contextual_indicators):
            return True

        # If none of the above criteria match, consider it not suspicious
        return False

    # combine list elements into single string
    def combine_list_elements(self, input_list, delimiter=" "):
        return delimiter.join(input_list)

    # Function to check if a process name matches cmd.exe or powershell.exe
    def is_command_or_powershell(self, process_name):
        return process_name.lower() in ["cmd.exe", "powershell.exe"]
    
    # Get running command and powershell processes
    def get_command_and_powershell_processes(self):
        return set(p.info['pid'] for p in psutil.process_iter(attrs=['name', 'pid']) if self.is_command_or_powershell(p.info['name']))

    def monitor_processes(self):
        # Store the initial list of running command and PowerShell processes
        initial_processes = self.get_command_and_powershell_processes()

        while self.active:
            # Get the list of currently running command and PowerShell processes
            current_processes = self.get_command_and_powershell_processes()

            # Find new processes
            new_processes = current_processes - initial_processes

            # Log the new processes, if cmd is suspicious, output pid, location and cmd run
            if new_processes:
                for pid in new_processes:
                    try:
                        process = psutil.Process(pid)
                        cmd_line = self.combine_list_elements(process.cmdline())
                        if cmd_line and self.is_suspicious(cmd_line):
                            title = "New suspicious CLI processes detected:"
                            message = f"Process ID: {pid}, Command: {' '.join(process.cmdline())}"
                            # creates windows notification warning user of suspicious cmds being run
                            self.notify(title + "\n" + message)
                            logging.warning(f"Suspicious process detected - PID: {pid}, Command: {cmd_line}")
                    except psutil.NoSuchProcess:
                        pass

            # Update the initial list of processes
            initial_processes = current_processes

            # Sleep for a while to reduce CPU usage
            # time.sleep(1)

if __name__ == "__main__":
    cli_monitor = CLIMonitor()  # Create an instance of the CLIMonitor class
    cli_monitor.start_monitoring()  # Send the initial notification
    cli_monitor.monitor_processes()  # Start monitoring processes