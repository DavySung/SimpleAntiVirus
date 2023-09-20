import os
import shutil
import subprocess
from tkinter import *


def main():
    apath = input("Please enter file location address (including file extension): ")
    apath = apath.rsplit('\\', 1)
    filedir = apath[0]
    fname = apath[1]
    quarantine(filedir, fname)


def quarantine(pfiledir, pfilename):
    dir_name = "Quarantine"
    f = open('quarantine.txt', 'w')
    f.write(pfilename + ', ' + pfiledir)
    f.close()
    shutil.move(pfiledir + '\\' + pfilename, dir_name)
    subprocess.check_output(['icacls.exe', dir_name + '\\' + pfilename, '/deny', 'everyone:(f)'], stderr=subprocess.STDOUT)


def restore(psource_name, pdest_name):
    shutil.move(psource_name, pdest_name)


main()
# Delete or restore file
choice = input("Would you like to (D)elete or (R)estore?: ")

with open('Quarantine.txt') as f:
    filename = f.readline()
    filename = filename.split(',')

subprocess.check_output(['icacls.exe', 'Quarantine\\' + filename[0], '/GRANT', 'everyone:(f)'], stderr=subprocess.STDOUT)

if choice == 'D':
    file_path = 'Quarantine\\' + filename[0]
    os.remove(file_path)
    print("Deleted.")
elif choice == 'R':
    os.chdir('Quarantine')
    path = os.getcwd()
    source_name = path + '\\' + filename[0]
    dest_name = filename[1].rsplit('\\', 1)
    os.chdir(dest_name[0].strip())
    restore(source_name, dest_name[1])
    print("Restored.")

else:
    print("No valid option selected, closing...")
