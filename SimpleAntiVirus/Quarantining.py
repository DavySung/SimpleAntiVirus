import os
import shutil
import subprocess
import tkinter as tk
from tkinter import messagebox


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
        msg_box = tk.messagebox.askquestion(' ', 'Delete identified file?', icon='warning')

        with open('Quarantine.txt') as f:
            filename = f.readline()
            filename = filename.split(',')

        subprocess.check_output(['icacls.exe', 'Quarantine\\' + filename[0], '/GRANT', 'everyone:(f)'], stderr=subprocess.STDOUT)

        if msg_box == 'yes':
            file_path = 'Quarantine\\' + filename[0]
            os.remove(file_path)
            print("Deleted.")
        else:
            tk.messagebox.showinfo(' ', 'File will be restored to original location')
            os.chdir('Quarantine')
            path = os.getcwd()
            source_name = path + '\\' + filename[0]
            dest_name = filename[1].rsplit('\\', 1)
            os.chdir(dest_name[0].strip())
            self.restore_file(source_name, dest_name[1])


if __name__ == '__main__':
    quarantine = Quarantine()
