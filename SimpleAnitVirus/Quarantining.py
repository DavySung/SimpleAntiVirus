import os
import shutil
import stat

from pkg_resources._vendor.more_itertools import strip


def main():
    apath = input("Please enter file location address (including file extension): ")
    apath = apath.rsplit('\\', 1)
    filedir = apath[0]
    filename = apath[1]
    quarantine(filedir, filename)


def quarantine(pfiledir, pfilename):
    dir_name = "Quarantine"
    f = open('quarantine.txt', 'w')
    f.write(pfilename + ', ' + pfiledir)
    f.close()
    shutil.move(pfiledir + '\\' + pfilename, dir_name)


def restore(psource_name, pdest_name):
    shutil.move(psource_name, pdest_name)


main()
# Delete or restore file
choice = input("Would you like to (D)elete or (R)estore?: ")

with open('Quarantine.txt') as f:
    filename = f.readline()
    filename = filename.split(',')

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
