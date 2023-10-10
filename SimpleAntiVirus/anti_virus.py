import hashlib
import subprocess
import tkinter
from tkinter import *
import customtkinter
from filehash import HashFile
from CLIMonitor import CLIMonitor
from Quarantining import Quarantine
from malware_scan import MalScan
from tkinter import Label, StringVar, filedialog


customtkinter.set_appearance_mode("light")


class App(customtkinter.CTk):
    global CLIMonitorProcess
    CLIMonitorProcess = None
    
    def __init__(self):
        super().__init__()

        self.title("Simple Anti Virus")
        self.geometry("1000x600")
        self.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        self.grid_rowconfigure((0, 1,2), weight=1)

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
        new_window = customtkinter.CTkToplevel(self)
        file = HashFile()

        file1 = StringVar()
        file2 = StringVar()
        Sha256file1 = StringVar()
        Sha256file2 = StringVar()
        MD5file1 = StringVar()
        MD5file2 = StringVar()
        Sha1file1 = StringVar()
        Sha1file2 = StringVar()

        new_window.title("Hash File")
        new_window.geometry("1000x600")
        new_window.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        new_window.grid_rowconfigure((0, 1,2,3,4, 5,6,7,8,9, 10), weight=1)

        #hashfile1
        new_window.f1Lbl = customtkinter.CTkLabel(new_window, textvariable=file1, width=100)
        new_window.f1Lbl.grid(row=0, column=0, padx=5, pady=10, sticky="ew")
        file1.set("Open File 1 or enter the hash below")

        new_window.f1HashLbl3 = customtkinter.CTkLabel(new_window, text="Sha256 : ", width=100)
        new_window.f1HashLbl3.grid(row=1, column=0, padx=5, pady=10, sticky="ew")

        new_window.f1Sha256 = customtkinter.CTkEntry(new_window, textvariable=Sha256file1, width=100)
        new_window.f1Sha256.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        new_window.md5LblF1 = customtkinter.CTkLabel(new_window, text="MD5 : ")
        new_window.md5LblF1.grid(row=2, column=0, padx=5, pady=10, sticky="ew")

        new_window.f1MD5 = customtkinter.CTkEntry(new_window, textvariable=MD5file1, width=100)
        new_window.f1MD5.grid(row=2, column=1, padx=5, pady=10, sticky="ew")

        new_window.sha1LblF1 = customtkinter.CTkLabel(new_window, text="Sha1 : ")
        new_window.sha1LblF1.grid(row=3, column=0, padx=5, pady=10, sticky="ew")

        new_window.f1Sha1 = customtkinter.CTkEntry(new_window, textvariable=Sha1file1, width=100)
        new_window.f1Sha1.grid(row=3, column=1, padx=5, pady=10, sticky="ew")

        new_window.openF1 = customtkinter.CTkButton(new_window, text="Open File 1", command=lambda: self.open_file_dialog( file1, Sha256file1, MD5file1, Sha1file1))
        new_window.openF1.grid(row=4, column=3, padx=5, pady=10, sticky="ew")
       
        #hashfile2
        new_window.f2Lbl = customtkinter.CTkLabel(new_window, textvariable=file2, width=100)
        new_window.f2Lbl.grid(row=5, column=0, padx=5, pady=10, sticky="ew")
        file2.set("Open File 2 or enter the hash below")

        new_window.f2HashLbl3 = customtkinter.CTkLabel(new_window, text="Sha256 : ")
        new_window.f2HashLbl3.grid(row=6, column=0, padx=5, pady=10, sticky="ew")

        new_window.f2Sha256 = customtkinter.CTkEntry(new_window, textvariable=Sha256file2, width=100)
        new_window.f2Sha256.grid(row=6, column=1, padx=5, pady=10, sticky="ew")

        new_window.md5LblF2 = customtkinter.CTkLabel(new_window, text="MD5 : ")
        new_window.md5LblF2.grid(row=7, column=0, padx=5, pady=10, sticky="ew")

        new_window.f2MD5 = customtkinter.CTkEntry(new_window, textvariable=MD5file2, width=100)
        new_window.f2MD5.grid(row=7, column=1, padx=5, pady=10, sticky="ew")

        new_window.sha1LblF2 = customtkinter.CTkLabel(new_window, text="Sha1 : ")
        new_window.sha1LblF2.grid(row=8, column=0, padx=5, pady=10, sticky="ew")

        new_window.f2Sha1 = customtkinter.CTkEntry(new_window, textvariable=Sha1file2, width=100)
        new_window.f2Sha1.grid(row=8, column=1, padx=5, pady=10, sticky="ew")

        new_window.openF2 = customtkinter.CTkButton(new_window, text="Open File 2", command=lambda: self.open_file_dialog( file2, Sha256file2, MD5file2, Sha1file2))
        new_window.openF2.grid(row=9, column=3, padx=5, pady=10, sticky="ew")
       
        #Hash Function
        new_window.checkHash = customtkinter.CTkButton(new_window, text="Compare Two Hash", command=lambda: file.CheckHash(new_window.f1Sha256.get(),new_window.f2Sha256.get(), new_window.f1MD5.get(),new_window.f2MD5.get(), new_window.f1Sha1.get(),new_window.f2Sha1.get()))
        new_window.checkHash.grid(row=10, column=0, padx=5, pady=5, sticky="ew")

        new_window.storeMalicious = customtkinter.CTkButton(new_window, text="Store Malicious", command=lambda: file.StoreFile("malicious_file.txt", new_window.f1Sha256.get()))
        new_window.storeMalicious.grid(row=10, column=1, padx=5, pady=10, sticky="ew")

        new_window.storeTrusted = customtkinter.CTkButton(new_window, text="Store Trusted", command=lambda: file.StoreFile("trusted_file.txt", new_window.f1Sha256.get()))
        new_window.storeTrusted.grid(row=10, column=2, padx=5, pady=10, sticky="ew")

        new_window.checkMalicious = customtkinter.CTkButton(new_window, text="Check Malicious", command=lambda: file.CheckFile("malicious_file.txt", new_window.f1Sha256.get()))
        new_window.checkMalicious.grid(row=10, column=3, padx=5, pady=10, sticky="ew")

        new_window.checkTrusted = customtkinter.CTkButton(new_window, text="Check Trusted", command=lambda: file.CheckFile("trusted_file.txt", new_window.f1Sha256.get()))
        new_window.checkTrusted.grid(row=10, column=4, padx=5, pady=10, sticky="ew")

        new_window.back = customtkinter.CTkButton(new_window, text="Go Back", command=self.goBack)
        new_window.back.grid(row=10, column=5, padx=5, pady=10, sticky="ew")

        self.withdraw()

    def monitoring_window(self):
        #Opens second window from monitoring button
        monitoring_window = customtkinter.CTkToplevel(self)
        monitoring_window.title("Monitoring")
        monitoring_window.geometry("1000x600")
        monitoring_window.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        monitoring_window.grid_rowconfigure((0,1,2,3,4,5,6), weight=1)

        #Back to menu button
        monitoring_backbutton = customtkinter.CTkButton(monitoring_window, text="Go Back", command=self.goBack)
        monitoring_backbutton.grid(row=3, column=4, padx=5, pady=10, sticky="ew")
         
        #Button to turn off monitoring
        self.toggle_button = customtkinter.CTkButton(monitoring_window, text="Turn On", command=self.toggle_monitor)
        self.toggle_button.grid(row=3, column=2, padx=5, pady=10, sticky="ew")

        self.withdraw()

    def toggle_monitor(self):
        global CLIMonitorProcess
    # Toggle the state between On and Off
        if CLIMonitorProcess is None:
            # Code to turn on
            self.toggle_button.configure(text="Turn Off")
            CLIMonitorProcess = subprocess.Popen(['python', 'SimpleAntiVirus/CLIMonitor.py'])
            
        else:
            # Code to turn off
            self.toggle_button.configure(text="Turn On")
            CLIMonitorProcess.terminate()
            self.monitor.stop_monitoring()
            CLIMonitorProcess = None

    def quarantine_window(self):
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
        filepath = filedialog.askopenfilename()

        result = malScanner.scan(filepath)
        #resultText.insert(result)


    def button_full_scan(self, malScanner):

        malScanner.full_scan()


    def malware_scan_window(self):
        mal_scan_window = customtkinter.CTkToplevel(self)
        MalwareScanner = MalScan()

        mal_scan_window.title("Malware Scan")
        mal_scan_window.geometry("1000x600")
        mal_scan_window.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        mal_scan_window.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)

        # Back to menu button
        mal_scan_backbutton = customtkinter.CTkButton(mal_scan_window, text="Go Back", command=self.goBack)
        mal_scan_backbutton.grid(row=6, column=5, padx=5, pady=10, sticky="ew")

        mal_scan_quick = customtkinter.CTkButton(mal_scan_window, text="Quick Scan", command=lambda: self.open_dialog_quick_scan(MalwareScanner))
        mal_scan_quick.grid(row=6, column=3, padx=5, pady=10, sticky="ew")

        mal_scan_full = customtkinter.CTkButton(mal_scan_window, text="Full Scan", command=lambda: self.button_full_scan(MalwareScanner))
        mal_scan_full.grid(row=6, column=1, padx=5, pady=10, sticky="ew")

        resultText = customtkinter.CTkTextbox(mal_scan_window, width=400, corner_radius=0)
        resultText.grid(row=1, column=1, sticky="nsew")

        #resultText.insert("0.0", "Some example text!\n" * 50)

        self.withdraw()

        
if __name__ == "__main__":
    app = App()
    cli_monitor = CLIMonitor()
    app.monitor = cli_monitor  # Pass the CLIMonitor instance to your App instance
    quarantine = Quarantine()
    app.mainloop()

