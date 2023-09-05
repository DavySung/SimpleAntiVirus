from tkinter import *
import customtkinter

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

        self.button3 = customtkinter.CTkButton(self, text="File Hash", command=self.button_callback)
        self.button3.grid(row=1, column=3, padx=5, pady=10, sticky="ew")
        
        self.button4 = customtkinter.CTkButton(self, text="Quarantine", command=self.button_callback)
        self.button4.grid(row=1, column=4, padx=5, pady=10, sticky="ew")
        
        self.button5 = customtkinter.CTkButton(self, text="Web Filter", command=self.button_callback)
        self.button5.grid(row=1, column=5, padx=5, pady=10, sticky="ew")

    def button_callback(self):
        print("button pressed")

app = App()
app.mainloop()


