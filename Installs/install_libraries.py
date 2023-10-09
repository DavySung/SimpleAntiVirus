import subprocess

# Function to install libraries from requirements.txt
def install_libraries():
    try:
        with open('requirements.txt', 'r') as requirements_file:
            libraries = [line.strip() for line in requirements_file.readlines()]

        for library in libraries:
            subprocess.check_call(['pip', 'install', '--upgrade', library])


        print("All required libraries have been successfully installed!")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    install_libraries()
