import subprocess
import platform

def run_powershell_command(command):
    try:
        if platform.system() == "Windows":
            # Use PowerShell on Windows
            subprocess.run(['powershell', '-Command', command], check=True)
        else:
            print("PowerShell is not available on non-Windows systems.")
    except subprocess.CalledProcessError as e:
        print(f"Error running PowerShell command: {e}")

if __name__ == "__main__":
    powershell_command = "Get-ChildItem"  # You can replace this with any PowerShell command you want
    run_powershell_command(powershell_command)
