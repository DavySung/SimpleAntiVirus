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
        try:
            with open(filename, 'rb') as file:
                while True:
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except PermissionError:
            return ""

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
        result_window.geometry("400x200")
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

    def StoreFileFunction(self, fileName, text):
        try:
            flag = False
            fileName1 = 'malicious_file.txt'
            fileName2 = 'trusted_file.txt'
            file_result = self.CheckFileFunction(fileName1, fileName2,text)
            print(file_result)
            with open(fileName, "a+") as file:
                if(file_result == True):
                    flag = False
                else:
                    if(os.stat(fileName).st_size == 0):
                        file.write(text)
                        file.write("\n")
                        flag = True
                    else:
                        with open(fileName, "r") as file1:
                            Lines = file1.readlines()
                            for line in Lines:
                                if(text == line.strip()):
                                    flag = False
                                    break
                                else:
                                    file.write(text)
                                    file.write("\n")
                                    flag = True
                                    break
                return flag
        except:
            logging.exception("Exception in check hash")
            return False

    def StoreFile(self, fileName, text):
        try:
            result_window = customtkinter.CTk() 
            result_window.title("Store HashFile")
            result_window.geometry("400x200")
            result_window.grid_columnconfigure((0,1,2), weight=1)
            result_window.grid_rowconfigure((0, 1,2), weight=1)
            msg = ''
            result = self.StoreFileFunction(fileName, text)
            if(result == True):
                msg += 'File is stored successfully'
            else:
                msg += 'Cannot Store File\n\nFile existed'

            result_window.label = customtkinter.CTkLabel(result_window, text=msg, fg_color="transparent")
            result_window.label.grid(row=1, column=0, padx=5, pady=10, sticky="ew")
            result_window.mainloop()
        except:
            logging.exception("Exception in check hash")

    #Check if file exist in both malicious and trusted file
    def CheckFileFunction(self,fileName1, fileName2 ,text):
        flag = False
        with open(fileName1, "r") as file1:
                Lines = file1.readlines()
                for line in Lines:
                    if(text == line.strip()):
                        flag = True
                    else: 
                        flag = False
                if(flag == False):
                    with open(fileName2, "r") as file2:
                        lines2 = file2.readlines()
                        for line in lines2:
                            if(text == line.strip()):
                                flag = True
                            else: 
                                flag = False
                return flag


    def CheckFile(self, fileName, text):
        try:
            result_window = customtkinter.CTk() 
            result_window.title("Check File")
            result_window.geometry("400x200")
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
                            output += 'It is a corrupted file'
                            break
                        if(fileName == "trusted_file.txt"):
                            output += 'It is a trusted file'
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
