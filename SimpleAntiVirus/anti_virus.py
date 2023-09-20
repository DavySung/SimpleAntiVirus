from tkinter import *
import customtkinter
from filehash import HashFile
from tkinter import Label, StringVar, filedialog


customtkinter.set_appearance_mode("light")
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Simple Anti Virus")
        self.geometry("1000x600")
        self.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        self.grid_rowconfigure((0, 1,2), weight=1)

        self.button1 = customtkinter.CTkButton(self, text="Monitoring", command=self.button_callback)
        self.button1.grid(row=1, column=1, padx=5, pady=15, sticky="ew")

        self.button2 = customtkinter.CTkButton(self, text="File Scan", command=self.button_callback)
        self.button2.grid(row=1, column=2, padx=5, pady=20, sticky="ew")

        self.fileHashBtn = customtkinter.CTkButton(self, text="File Hash", command=self.hashWindow)
        self.fileHashBtn.grid(row=1, column=3, padx=5, pady=10, sticky="ew")
        
        self.button4 = customtkinter.CTkButton(self, text="Quarantine", command=self.button_callback)
        self.button4.grid(row=1, column=4, padx=5, pady=10, sticky="ew")
        
        self.button5 = customtkinter.CTkButton(self, text="Web Filter", command=self.button_callback)
        self.button5.grid(row=1, column=5, padx=5, pady=10, sticky="ew")

    def button_callback(self):
        print("button pressed")

    def goBack(self):
        self.destroy()

    def open_file_dialog(self, file_path, sha256):
        self.filename = filedialog.askopenfilename()
        file_path.set(self.filename)
        if file_path:
            file = HashFile()
            file.fileName = self.filename
            output = file.hash_file() 
            sha256.set(output)

    def hashWindow(self):
        new_window = customtkinter.CTkToplevel(self)
        file = HashFile()

        f1 = StringVar()
        f2 = StringVar()
        Sha256f1 = StringVar()
        Sha256f2 = StringVar()
        # MD5f1 = StringVar()
        # MD5f2 = StringVar()
        # Sha1f1 = StringVar()
        # Sha1f2 = StringVar()

        new_window.title("HashFile")
        new_window.geometry("1000x600")
        new_window.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        new_window.grid_rowconfigure((0, 1,2,3,4, 5,6), weight=1)

        #hashfile1
        new_window.f1Lbl = Label(new_window, textvariable=f1, width=60, anchor=W)
        new_window.f1Lbl.grid(row=0, column=0, padx=5, pady=10, sticky="ew")
        f1.set("First file or enter a HASH below.")

        new_window.f1HashLbl3 = customtkinter.CTkLabel(new_window, text="Sha256 : ", width=10, anchor=W)
        new_window.f1HashLbl3.grid(row=1, column=0, padx=5, pady=10, sticky="ew")

        new_window.f1Sha256 = customtkinter.CTkEntry(new_window, textvariable=Sha256f1, width=100)
        new_window.f1Sha256.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        new_window.openF1 = customtkinter.CTkButton(new_window, text="Open File 1", command=lambda: self.open_file_dialog( f1, Sha256f1))
        new_window.openF1.grid(row=1, column=3, padx=5, pady=10, sticky="ew")
       
        #hashfile2
        new_window.f2Lbl = Label(new_window, textvariable=f2, width=60, anchor=W)
        new_window.f2Lbl.grid(row=2, column=0, padx=5, pady=10, sticky="ew")
        f2.set("Second file or enter a HASH below.")

        new_window.f2HashLbl3 = customtkinter.CTkLabel(new_window, text="Sha256 : ")
        new_window.f2HashLbl3.grid(row=3, column=0, padx=5, pady=10, sticky="ew")

        new_window.f2Sha256 = customtkinter.CTkEntry(new_window, textvariable=Sha256f2, width=100)
        new_window.f2Sha256.grid(row=3, column=1, padx=5, pady=10, sticky="ew")

        new_window.openF2 = customtkinter.CTkButton(new_window, text="Open File 2", command=lambda: self.open_file_dialog( f2, Sha256f2))
        new_window.openF2.grid(row=3, column=3, padx=5, pady=10, sticky="ew")
       
        #Hash Function
        new_window.checkHash = customtkinter.CTkButton(new_window, text="Compare Two Hash", command=lambda: file.CheckHash(new_window.f1Sha256.get(),new_window.f2Sha256.get()))
        new_window.checkHash.grid(row=4, column=0, padx=5, pady=5, sticky="ew")

        new_window.storeMalicious = customtkinter.CTkButton(new_window, text="Store Malicious", command=lambda: file.StoreFile("malicious_file.txt", new_window.f1Sha256.get()))
        new_window.storeMalicious.grid(row=4, column=1, padx=5, pady=10, sticky="ew")

        new_window.storeTrusted = customtkinter.CTkButton(new_window, text="Store Trusted", command=lambda: file.StoreFile("trusted_file.txt", new_window.f1Sha256.get()))
        new_window.storeTrusted.grid(row=4, column=2, padx=5, pady=10, sticky="ew")

        new_window.checkMalicious = customtkinter.CTkButton(new_window, text="Check Malicious", command=lambda: file.CheckFile("malicious_file.txt", new_window.f1Sha256.get()))
        new_window.checkMalicious.grid(row=4, column=3, padx=5, pady=10, sticky="ew")

        new_window.checkTrusted = customtkinter.CTkButton(new_window, text="Check Trusted", command=lambda: file.CheckFile("trusted_file.txt", new_window.f1Sha256.get()))
        new_window.checkTrusted.grid(row=4, column=4, padx=5, pady=10, sticky="ew")

        new_window.back = customtkinter.CTkButton(new_window, text="Go Back", command=self.goBack)
        new_window.back.grid(row=4, column=5, padx=5, pady=10, sticky="ew")

        self.withdraw()

app = App()
app.mainloop()


