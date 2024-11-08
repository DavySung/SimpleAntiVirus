import hashlib
import subprocess
import tkinter
import tkinter.messagebox
from tkinter import *
from tkinter import font
import customtkinter
from filehash import HashFile
from CLIMonitor import CLIMonitor
from Quarantining import *
from malware_scan import MalScan
from tkinter import Label, StringVar, filedialog

customtkinter.set_appearance_mode("light")


class App(customtkinter.CTk):
    global CLIMonitorProcess
    CLIMonitorProcess = None
    cli_monitor = None  # Class variable to store CLIMonitor instance

    def __init__(self):
        super().__init__()
        
        self.title("Simple Anti Virus")
        self.geometry("1000x600")
        self.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        self.grid_rowconfigure((0, 1,2), weight=1)

        self.titleLabel = customtkinter.CTkLabel(self, text="SIMPLE ANTI VIRUS", width=200,
                               height=25, font=("Helvetica bold", 30))
        self.titleLabel.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

        self.button1 = customtkinter.CTkButton(self, text="Monitoring", command=self.monitoring_window)
        self.button1.grid(row=1, column=1, padx=5, pady=15, sticky="ew")

        self.button2 = customtkinter.CTkButton(self, text="File Scan", command=self.malware_scan_window)
        self.button2.grid(row=1, column=2, padx=5, pady=10, sticky="ew")

        self.fileHashBtn = customtkinter.CTkButton(self, text="File Hash", command=self.hashWindow)
        self.fileHashBtn.grid(row=1, column=3, padx=5, pady=10, sticky="ew")

        self.button4 = customtkinter.CTkButton(self, text="Quarantine", command=self.quarantine_window)
        self.button4.grid(row=1, column=4, padx=5, pady=10, sticky="ew")
        

    def button_callback(self):
        print("button pressed")

    def goBack(self):
        self.destroy()
        main_menu_window = App()
        main_menu_window.mainloop()

    def open_file_dialog(self, file_path, sha256, md5, sha1):
        self.filename = filedialog.askopenfilename()
        file_path.set(self.filename)
        if file_path:
            file = HashFile()
            file.fileName = self.filename
            sha256_output = file.hash_file(self.filename, hashlib.sha256()) 
            sha256.set(sha256_output)
            md5_output = file.hash_file(self.filename, hashlib.md5()) 
            md5.set(md5_output)
            sha1_output = file.hash_file(self.filename, hashlib.sha1()) 
            sha1.set(sha1_output)

    def hashWindow(self):
        hash_window = customtkinter.CTkToplevel(self)
        file = HashFile()

        file1 = StringVar()
        file2 = StringVar()
        Sha256file1 = StringVar()
        Sha256file2 = StringVar()
        MD5file1 = StringVar()
        MD5file2 = StringVar()
        Sha1file1 = StringVar()
        Sha1file2 = StringVar()

        hash_window.title("Hash File")
        hash_window.geometry("1200x600")
        hash_window.grid_columnconfigure((0,1,2), weight=1)
        hash_window.grid_rowconfigure((0, 1,2,3,4, 5,6,7,8,9, 10,11, 12), weight=1)
        
        #title
        hash_window.titleLabel = customtkinter.CTkLabel(hash_window, text="Hash File", width=200,
                               height=25, font=("Helvetica bold", 30))
        hash_window.titleLabel.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        hash_window.file1Label = customtkinter.CTkLabel(hash_window, text="Open File1 for storing or checking in storage OR \nOpen both files to compare", width=200,
                               height=25, font=("Helvetica bold", 18))
        hash_window.file1Label.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        hash_window.openF1 = customtkinter.CTkButton(hash_window, text="Open File 1", command=lambda: self.open_file_dialog( file1, Sha256file1, MD5file1, Sha1file1))
        hash_window.openF1.grid(row=1, column=2, padx=5, pady=10, sticky="ew")

        hash_window.openF2 = customtkinter.CTkButton(hash_window, text="Open File 2", command=lambda: self.open_file_dialog( file2, Sha256file2, MD5file2, Sha1file2))
        hash_window.openF2.grid(row=2, column=2, padx=5, pady=10, sticky="ew")

        #hashfile1
        hash_window.f1Lbl = customtkinter.CTkLabel(hash_window, textvariable=file1, font=("Helvetica bold", 18))
        hash_window.f1Lbl.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        file1.set('Hash Format 1')

        hash_window.f1HashLbl3 = customtkinter.CTkLabel(hash_window, text="Sha256 : ", width=100)
        hash_window.f1HashLbl3.grid(row=3, column=0, padx=5, pady=10, sticky="ew")

        hash_window.f1Sha256 = customtkinter.CTkEntry(hash_window, textvariable=Sha256file1, width=100)
        hash_window.f1Sha256.grid(row=3, column=1, padx=5, pady=10, sticky="ew")

        hash_window.md5LblF1 = customtkinter.CTkLabel(hash_window, text="MD5 : ")
        hash_window.md5LblF1.grid(row=4, column=0, padx=5, pady=10, sticky="ew")

        hash_window.f1MD5 = customtkinter.CTkEntry(hash_window, textvariable=MD5file1, width=100)
        hash_window.f1MD5.grid(row=4, column=1, padx=5, pady=10, sticky="ew")

        hash_window.sha1LblF1 = customtkinter.CTkLabel(hash_window, text="Sha1 : ")
        hash_window.sha1LblF1.grid(row=5, column=0, padx=5, pady=10, sticky="ew")

        hash_window.f1Sha1 = customtkinter.CTkEntry(hash_window, textvariable=Sha1file1, width=100)
        hash_window.f1Sha1.grid(row=5, column=1, padx=5, pady=10, sticky="ew")
       
        #hashfile2

        hash_window.f2Lbl = customtkinter.CTkLabel(hash_window, textvariable=file2, width=200,font=("Helvetica bold", 18) )
        hash_window.f2Lbl.grid(row=6, column=1, padx=5, pady=10, sticky="ew")
        file2.set('Hash Format 2')

        hash_window.f2HashLbl3 = customtkinter.CTkLabel(hash_window, text="Sha256 : ")
        hash_window.f2HashLbl3.grid(row=7, column=0, padx=5, pady=10, sticky="ew")

        hash_window.f2Sha256 = customtkinter.CTkEntry(hash_window, textvariable=Sha256file2, width=100)
        hash_window.f2Sha256.grid(row=7, column=1, padx=5, pady=10, sticky="ew")

        hash_window.md5LblF2 = customtkinter.CTkLabel(hash_window, text="MD5 : ")
        hash_window.md5LblF2.grid(row=8, column=0, padx=5, pady=10, sticky="ew")

        hash_window.f2MD5 = customtkinter.CTkEntry(hash_window, textvariable=MD5file2, width=100)
        hash_window.f2MD5.grid(row=8, column=1, padx=5, pady=10, sticky="ew")

        hash_window.sha1LblF2 = customtkinter.CTkLabel(hash_window, text="Sha1 : ")
        hash_window.sha1LblF2.grid(row=9, column=0, padx=5, pady=10, sticky="ew")

        hash_window.f2Sha1 = customtkinter.CTkEntry(hash_window, textvariable=Sha1file2, width=100)
        hash_window.f2Sha1.grid(row=9, column=1, padx=5, pady=10, sticky="ew")
        
        hash_window.empltyGrid = customtkinter.CTkLabel(hash_window, text="")
        hash_window.empltyGrid.grid(row=10, column=0, padx=5, pady=5, sticky="ew")
        #Hash Function
        hash_window.checkHash = customtkinter.CTkButton(hash_window, text="Compare Two Hash", command=lambda: file.CheckHashInterface(hash_window.f1Sha256.get(),hash_window.f2Sha256.get(), hash_window.f1MD5.get(),hash_window.f2MD5.get(), hash_window.f1Sha1.get(),hash_window.f2Sha1.get()))
        hash_window.checkHash.grid(row=11, column=0, padx=5, pady=5, sticky="ew")

        hash_window.storeMalicious = customtkinter.CTkButton(hash_window, text="Store Malicious", command=lambda: file.StoreFile("malicious_file.txt", hash_window.f1Sha256.get()))
        hash_window.storeMalicious.grid(row=11, column=1, padx=5, pady=10, sticky="ew")

        hash_window.storeTrusted = customtkinter.CTkButton(hash_window, text="Store Trusted", command=lambda: file.StoreFile("trusted_file.txt", hash_window.f1Sha256.get()))
        hash_window.storeTrusted.grid(row=11, column=2, padx=5, pady=10, sticky="ew")

        hash_window.checkMalicious = customtkinter.CTkButton(hash_window, text="Check Malicious", command=lambda: file.CheckFile("malicious_file.txt", hash_window.f1Sha256.get()))
        hash_window.checkMalicious.grid(row=12, column=0, padx=5, pady=10, sticky="ew")

        hash_window.checkTrusted = customtkinter.CTkButton(hash_window, text="Check Trusted", command=lambda: file.CheckFile("trusted_file.txt", hash_window.f1Sha256.get()))
        hash_window.checkTrusted.grid(row=12, column=1, padx=5, pady=10, sticky="ew")

        hash_window.back = customtkinter.CTkButton(hash_window, text="Go Back", command=self.goBack)
        hash_window.back.grid(row=12, column=2, padx=5, pady=10, sticky="ew")

        self.withdraw()

    def monitoring_window(self):
        #Opens second window from monitoring button
        monitoring_window = customtkinter.CTkToplevel(self)
        monitoring_window.title("Monitoring")
        monitoring_window.geometry("1000x600")
        monitoring_window.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        monitoring_window.grid_rowconfigure((0,1,2,3,4,5,6), weight=1)

        #title
        monitoring_window.titleLabel = customtkinter.CTkLabel(monitoring_window, text="CLI Monitor", width=200,
                               height=25, font=("Helvetica bold", 30))
        monitoring_window.titleLabel.grid(row=0, column=3, padx=5, pady=10, sticky="ew")

        #Button to turn off monitoring
        self.toggle_button = customtkinter.CTkButton(monitoring_window, text="Turn On", command=self.toggle_monitor)
        self.toggle_button.grid(row=3, column=2, padx=5, pady=10, sticky="ew")
        self.check_state()

        #Back to menu button
        monitoring_backbutton = customtkinter.CTkButton(monitoring_window, text="Go Back", command=self.goBack)
        monitoring_backbutton.grid(row=3, column=4, padx=5, pady=10, sticky="ew")

        self.withdraw()

    def check_state(self):
        global CLIMonitorProcess
        if CLIMonitorProcess is None:
            self.toggle_button.configure(text="Turn On")
        else:
            self.toggle_button.configure(text="Turn Off")

    def toggle_monitor(self):
        global CLIMonitorProcess

        if CLIMonitorProcess is None:
            self.toggle_button.configure(text="Turn Off")
            self.cli_monitor = CLIMonitor()
            CLIMonitorProcess = subprocess.Popen(['python', 'CLIMonitor.py'])
        else:
            self.toggle_button.configure(text="Turn On")
            if self.cli_monitor:
                self.cli_monitor.stop_monitoring()
            if CLIMonitorProcess:
                CLIMonitorProcess.terminate()
            CLIMonitorProcess = None
            self.cli_monitor = None

    def quarantine_window(self):
        quarantine = Quarantine()
        # Opens second window from quarantine button
        quarantine_window = customtkinter.CTkToplevel(self)
        quarantine_window.title("Quarantine")
        quarantine_window.geometry("1000x600")
        quarantine_window.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        quarantine_window.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)

        # Select file for quarantine
        select_button = customtkinter.CTkButton(quarantine_window, text="Select file", command=quarantine.get_file)
        select_button.grid(row=2, column=3, padx=5, pady=10, sticky="ew")

        # Puts file into quarantine
        quarantine_button = customtkinter.CTkButton(quarantine_window, text="Quarantine file", command=quarantine.quarantine_file)
        quarantine_button.grid(row=2, column=4, padx=5, pady=10, sticky="ew")

        # Restores file to original location
        restore_button = customtkinter.CTkButton(quarantine_window, text="Restore file", command=quarantine.restore_file)
        restore_button.grid(row=3, column=3, padx=5, pady=10, sticky="ew")

        # Deletes quarantined file
        delete_button = customtkinter.CTkButton(quarantine_window, text="Delete file", command=quarantine.delete_file)
        delete_button.grid(row=3, column=4, padx=5, pady=10, sticky="ew")

        # Back to menu button
        quarantine_backbutton = customtkinter.CTkButton(quarantine_window, text="Go Back", command=self.goBack)
        quarantine_backbutton.grid(row=10, column=5, padx=5, pady=10, sticky="ew")

        self.withdraw()

    def open_dialog_quick_scan(self, malScanner):
        filepath = filedialog.askdirectory()
        result = malScanner.scan(filepath)
        tkinter.messagebox.showinfo("Scan Results", result)

    def button_full_scan(self, malScanner):
        result = ""
        result += malScanner.full_scan()
        tkinter.messagebox.showinfo("Scan Results", result)
    def malware_scan_window(self):
        mal_scan_window = customtkinter.CTkToplevel(self)
        MalwareScanner = MalScan()

        mal_scan_window.title("Malware Scan")
        mal_scan_window.geometry("1000x600")
        mal_scan_window.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        mal_scan_window.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)

        # Title
        mal_scan_window.titleLabel = customtkinter.CTkLabel(mal_scan_window, text="Virus Scan", width=200,
                               height=25, font=("Helvetica bold", 30))
        mal_scan_window.titleLabel.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

        # Back to menu button
        mal_scan_backbutton = customtkinter.CTkButton(mal_scan_window, text="Go Back", command=self.goBack)
        mal_scan_backbutton.grid(row=4, column=5, padx=5, pady=10, sticky="ew")

        # Quick Scan Button
        mal_scan_quick = customtkinter.CTkButton(mal_scan_window, text="Quick Scan", command=lambda: self.open_dialog_quick_scan(MalwareScanner))
        mal_scan_quick.grid(row=4, column=3, padx=5, pady=10, sticky="ew")

        # Full Scan Button
        mal_scan_full = customtkinter.CTkButton(mal_scan_window, text="Full Scan", command=lambda: self.button_full_scan(MalwareScanner))
        mal_scan_full.grid(row=4, column=1, padx=5, pady=10, sticky="ew")

        self.withdraw()


if __name__ == "__main__":
    app = App()
    app.mainloop()
