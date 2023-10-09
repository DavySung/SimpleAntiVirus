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
        if hasattr(self, 'apath'):
            apath = self.apath
            apath = apath.rsplit('\\', 1)
            fdir = apath[0]
            fname = apath[1]
            dir_name = "Quarantine"
            with open('Quarantine.txt', 'w') as f:
                f.write(fname + ', ' + fdir)
            shutil.move(fdir + '\\' + fname, dir_name)
            subprocess.check_output(['icacls.exe', dir_name + '\\' + fname, '/deny', 'everyone:(f)'], stderr=subprocess.STDOUT)
        else:
            tk.messagebox.showerror("Error", "No file selected")

    def restore_file(self):
        with open('Quarantine.txt') as f:
            filename = f.readline()
            filename = filename.split(',')
        subprocess.check_output(['icacls.exe', 'Quarantine\\' + filename[0], '/GRANT', 'everyone:(f)'],
                                stderr=subprocess.STDOUT)
        file_path = 'Quarantine\\' + filename[0]
        if os.path.exists(file_path):
            question = tk.messagebox.askquestion('Restore', 'Restore the file?', icon='warning')
            if question == 'yes':
                shutil.move(file_path, filename[1].strip())
                tk.messagebox.showinfo('Restore', 'File restore successful')
            else:
                tk.messagebox.showerror("Error", "No file found in quarantine")

    def delete_file(self):
        if self.apath:
            apath = self.apath
            apath = apath.rsplit('\\', 1)
            fdir = apath[0]
            fname = apath[1]
            file_path = 'Quarantine\\' + fname
            if os.path.exists(file_path):
                os.remove(file_path)
                tk.messagebox.showinfo('Delete', 'File delete successful')
            else:
                tk.messagebox.showerror("Error", "No file found in quarantine")
        else:
            tk.messagebox.showerror("Error", "No file selected for deletion")


if __name__ == '__main__':
    quarantine = Quarantine()
