import hashlib
import logging
import os
import customtkinter
# HashedFile: HashLib
# Hash(FilePath: string)
# CheckHash(Hash)
#This function check file hash integrity

# hash file content
# check file if it has been modified or corrupted
#Compare the file hash of a given file with a previous hash file copy of the same file
# And also allow user custom input hash files as malicious or to be trusted

#Integrity check for sensitive file 
class HashFile:
    def _init_(self, fileName):
        self.fileName = fileName

    def hash_file(self, filename, hash_obj):
        with open(self.fileName, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def CheckHash(self, sha256Output1, sha256Output2,md5Output1, md5Output2, sha1Output1, sha1Output2):
        try:
            flag = False
            if(sha256Output1 == sha256Output2 and sha1Output1 == sha1Output2 and md5Output1 == md5Output2):
                flag = True
            elif(sha256Output1 == sha256Output2 and sha1Output1 == sha1Output2 ):
                flag = True
            elif(sha256Output1 == sha256Output2 and md5Output1 == md5Output2):
                flag = True
            elif(sha1Output1 == sha1Output2 and md5Output1 == md5Output2):
                flag = True
            elif(sha256Output1 == sha256Output2 ):
                flag = True
            elif(sha1Output1 == sha1Output2 ):
                flag = True
            elif(md5Output1 == md5Output2):
                flag = True
            else:
                flag = False
            return flag
        except:
            logging.exception("Exception in check hash")
            return False
    
    def CheckHashInterface(self,sha256Output1, sha256Output2,md5Output1, md5Output2, sha1Output1, sha1Output2):
        result = ""
        result_window = customtkinter.CTk() 
        result_window.title("Check HashFile")
        result_window.geometry("600x200")
        result_window.grid_columnconfigure((0,1,2), weight=1)
        result_window.grid_rowconfigure((0, 1,2), weight=1)

        hash_result = self.CheckHash(sha256Output1, sha256Output2,md5Output1, md5Output2, sha1Output1, sha1Output2)

        if(hash_result == True):
            result += 'Hash are the same!\n'
        else:
            result += 'Hash are different'

        result_window.label = customtkinter.CTkLabel(result_window, text=result, fg_color="transparent")
        result_window.label.grid(row=1, column=0, padx=5, pady=10, sticky="ew")
        result_window.mainloop()

    def StoreFile(self, fileName, text):
        try:
            result_window = customtkinter.CTk() 
            result_window.title("Store HashFile")
            result_window.geometry("600x200")
            result_window.grid_columnconfigure((0,1,2), weight=1)
            result_window.grid_rowconfigure((0, 1,2), weight=1)
            flag = False
            msg = ''
            with open(fileName, "a+") as file:
                if(os.stat(fileName).st_size == 0):
                    file.write(text)
                    file.write("\n")
                    msg += 'File is stored'
                else:
                    with open(fileName, "r") as file1:
                        Lines = file1.readlines()
                        for line in Lines:
                            if(text == line.strip()):
                                msg += 'File existed'
                                flag = False
                                break
                            else:
                                flag = True
                        if(flag == True):
                            file.write(text)
                            file.write("\n")
                            msg += 'File is stored'
            result_window.label = customtkinter.CTkLabel(result_window, text=msg, fg_color="transparent")
            result_window.label.grid(row=1, column=0, padx=5, pady=10, sticky="ew")
            result_window.mainloop()
        except:
            logging.exception("Exception in check hash")
    
    def CheckFile(self, fileName, text):
        try:
            result_window = customtkinter.CTk() 
            result_window.title("Check File")
            result_window.geometry("600x200")
            result_window.grid_columnconfigure((0,1,2), weight=1)
            result_window.grid_rowconfigure((0, 1,2), weight=1)
            flag = False
            output = ''
            with open(fileName, "r") as file1:
                Lines = file1.readlines()
                for line in Lines:
                    if(text == line.strip()):
                        if(fileName == "malicious_file.txt"):
                            flag = True
                            output += 'File is corrupted'
                            break
                        if(fileName == "trusted_file.txt"):
                            output += 'File is trusted'
                            flag = True
                            break
                    else: 
                        flag = False
                if(flag == False):
                    output += "File not found"

            result_window.label = customtkinter.CTkLabel(result_window, text=output, fg_color="transparent")
            result_window.label.grid(row=1, column=0, padx=5, pady=10, sticky="ew")
            result_window.mainloop()
        except:
            logging.exception("Exception in check hash")
