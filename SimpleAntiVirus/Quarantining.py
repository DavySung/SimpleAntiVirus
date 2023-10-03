import os
import shutil
import subprocess


class Quarantine:
    def __init__(self):
        self.get_file()
        self.user_select()

    def get_file(self):
        apath = input("Please enter file location address (including file extension): ")
        apath = apath.rsplit('\\', 1)
        filedir = apath[0]
        fname = apath[1]
        self.quarantine_file(filedir, fname)

    def quarantine_file(self, pfiledir, pfilename):
        dir_name = "Quarantine"
        f = open('quarantine.txt', 'w')
        f.write(pfilename + ', ' + pfiledir)
        f.close()
        shutil.move(pfiledir + '\\' + pfilename, dir_name)
        subprocess.check_output(['icacls.exe', dir_name + '\\' + pfilename, '/deny', 'everyone:(f)'], stderr=subprocess.STDOUT)

    def restore_file(self, psource_name, pdestname):
        shutil.move(psource_name, pdestname)

    def user_select(self):
        # print("Would you like to remove the file?")
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
            # dest_name doesn't contain a '\'
            # E.g. I put the test.txt file directly into my D drive and in debugging, it shows dest_name only containing 'D:'
            os.chdir(dest_name[0].strip())
            self.restore_file(source_name, dest_name[1])
            print("Restored.")

        else:
            print("No valid option selected, closing...")


if __name__ == '__main__':
    quarantine = Quarantine()