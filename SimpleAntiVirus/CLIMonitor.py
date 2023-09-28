import psutil
import time
import subprocess
import tkinter as tk
from plyer import notification

active = True

if active:
    notification.notify(
                            title="CLI Monitor",
                            message="CLI Monitor Is now active",
                            app_name="SimpleAntivirus",
                            timeout=10
                        )
else:
    notification.notify(
                            title="CLI Monitor",
                            message="CLI Monitor Is no longer active",
                            app_name="SimpleAntivirus",
                            timeout=10
                        )

def is_suspicious(cmdline):
    # Convert the command line to lowercase for case-insensitive matching
    cmdline_lower = cmdline.lower()

    # Scans in known malicious domains into array
    known_mal_domains = "SimpleAntiVirus/scan_known_malware/malicious_domains.txt"
    with open(known_mal_domains, 'r') as file:
        malicious_domains = [line.strip() for line in file]

    # Suspicious keywords and phrases
    suspicious_keywords = ["Invoke-Expression", "Base64", "DownloadString", "/c", "dir", "Get-ChildItem"]
    for keyword in suspicious_keywords:
        if keyword.lower() in cmdline_lower:
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
    obfuscation_indicators = ["IEX", "Invoke-Expression"]
    for indicator in obfuscation_indicators:
        if indicator.lower() in cmdline_lower:
            return True

    # Network activity (e.g., downloading from suspicious URLs)
    if "-uri" in cmdline_lower and any(domain in cmdline_lower for domain in malicious_domains):
        return True

    # Suspicious parameters or arguments
    suspicious_parameters = ["-NoProfile", "-WindowStyle Hidden"]
    for param in suspicious_parameters:
        if param.lower() in cmdline_lower:
            return True

    # Contextual checks (e.g., execution from unusual locations)
    contextual_indicators = ["C:\\Temp\\", "Desktop\\"]
    for indicator in contextual_indicators:
        if indicator.lower() in cmdline_lower:
            return True

    # If none of the above criteria match, consider it not suspicious
    return False

# combine list elements into single string
def combine_list_elements(input_list, delimiter=" "):
    combined_string = delimiter.join(input_list)
    return combined_string

# Function to check if a process name matches cmd.exe or powershell.exe
def is_command_or_powershell(process_name):
    return process_name.lower() in ["cmd.exe", "powershell.exe"]

# Store the initial list of running command and PowerShell processes
initial_processes = set(p.info['pid'] for p in psutil.process_iter(attrs=['name', 'pid']) if is_command_or_powershell(p.info['name']))

while active:
    # Get the list of currently running command and PowerShell processes
    current_processes = set(p.info['pid'] for p in psutil.process_iter(attrs=['name', 'pid']) if is_command_or_powershell(p.info['name']))

    # Find new processes
    new_processes = current_processes - initial_processes

    # Log the new processes, if cmd is suspicious, output pid, location and cmd run
    if new_processes:
        for pid in new_processes:
            try:
                process = psutil.Process(pid)
                cmd_line = combine_list_elements(process.cmdline())
                if cmd_line and is_suspicious(cmd_line):
                    title = "New suspicious CLI processes detected:"
                    message = f"Process ID: {pid}, Command: {' '.join(process.cmdline())}"
                    # creates windows notification warning user of suspicious cmds being run
                    notification.notify(
                        title=title,
                        message=message,
                        app_name="SimpleAntivirus",
                        timeout=10
                    )
            except psutil.NoSuchProcess:
                pass

    # Update the initial list of processes
    initial_processes = current_processes

    # Sleep for a while to reduce CPU usage
    # time.sleep(1)
