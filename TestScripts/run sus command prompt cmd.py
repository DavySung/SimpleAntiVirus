import subprocess
import platform

def run_ls_command():
    try:
        if platform.system() == "Windows":
            # Use 'dir' command on Windows
            subprocess.run(['dir'], check=True, shell=True)
        else:
            # Use 'ls' command on Unix-like systems
            subprocess.run(['ls'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
    except FileNotFoundError:
        print("Command not found. Make sure you are running this on a supported system.")

if __name__ == "__main__":
    run_ls_command()
