import os
import shutil
import subprocess
import tkinter as tk
from tkinter import messagebox, filedialog


class Quarantine:
    def __init__(self):
        self.apath = None

    def get_file(self):
        apath = filedialog.askopenfilename()
        apath = apath.replace("/", "\\")
        if apath:
            self.apath = apath

    def quarantine_file(self):
        if self.apath is not None:
            apath = self.apath
            apath = apath.rsplit('\\', 1)
            fdir = apath[0]
            fname = apath[1]
            dir_name = "Quarantine"
            with open('Quarantine.txt', 'a') as f:
                f.write(fname + ', ' + fdir + '\n')
            shutil.move(fdir + '\\' + fname, dir_name)
            subprocess.check_output(['icacls.exe', dir_name + '\\' + fname, '/deny', 'everyone:(f)'], stderr=subprocess.STDOUT)
            tk.messagebox.showinfo('Quarantine', 'File quarantine successful')
        else:
            tk.messagebox.showerror("Error", "No file selected")

    def restore_file(self):
        with open('Quarantine.txt') as f:
            filename = f.readline()
            filename = filename.split(',')
        if filename != ['']:
            file_path = 'Quarantine\\' + filename[0]
            if os.path.exists(file_path):
                subprocess.check_output(['icacls.exe', 'Quarantine\\' + filename[0], '/GRANT', 'everyone:(f)'],
                                            stderr=subprocess.STDOUT)
                shutil.move(file_path, filename[1].strip())
                with open(r"Quarantine.txt", 'r+') as fp:
                    lines = fp.readlines()
                    fp.seek(0)
                    fp.truncate()
                    fp.writelines(lines[1:])
                tk.messagebox.showinfo('Restore', 'File restore successful')
            else:
                tk.messagebox.showerror("Error", "No file found in quarantine")
        else:
            tk.messagebox.showerror("Error", "No file selected")

    def delete_file(self):
        with open('Quarantine.txt') as f:
            filename = f.readline()
            filename = filename.split(',')
        if filename != ['']:
            file_path = 'Quarantine\\' + filename[0]
            if os.path.exists(file_path):
                os.remove(file_path)
                with open(r"Quarantine.txt", 'r+') as fp:
                    lines = fp.readlines()
                    fp.seek(0)
                    fp.truncate()
                    fp.writelines(lines[1:])
                tk.messagebox.showinfo('Delete', 'File delete successful')
            else:
                tk.messagebox.showerror("Error", "No file found in quarantine")
        else:
            tk.messagebox.showerror("Error", "No file selected")


if __name__ == '__main__':
    quarantine = Quarantine()
