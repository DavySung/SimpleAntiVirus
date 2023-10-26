import hashlib
import logging
import os
import tkinter
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
        with open(filename, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    #Compare all hash together
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
    
    #Checking hash individually
    def CheckOneHash(self, hash1, hash2):
        if(hash1 == hash2):
            return True
        else:
            return False

    #Checkhash User Interface
    def CheckHashInterface(self,sha256Output1, sha256Output2,md5Output1, md5Output2, sha1Output1, sha1Output2):

        hash_result = self.CheckHash(sha256Output1, sha256Output2,md5Output1, md5Output2, sha1Output1, sha1Output2)

        if(hash_result == True):
            tkinter.messagebox.showinfo('Hash File', 'Hash format are the same')
        else:
            tkinter.messagebox.showerror('Hash File', 'Hash format are different')

    #Store hash in local file
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

    #Store hash in local file with user interface
    def StoreFile(self, fileName, text):
        try:
            result = self.StoreFileFunction(fileName, text)
            if(result == True):
                tkinter.messagebox.showinfo('Hash File', 'File is stored successfully')
            else:
                tkinter.messagebox.showerror('Hash File', 'Cannot Store File\n\nFile existed')
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


    #Check hash in local file with user interface
    def CheckFile(self, fileName, text):
        try:
            flag = False
            with open(fileName, "r") as file1:
                Lines = file1.readlines()
                for line in Lines:
                    if(text == line.strip()):
                        if(fileName == "malicious_file.txt"):
                            flag = True
                            tkinter.messagebox.showinfo('Check File', 'It is a corrupted file')
                         
                            break
                        if(fileName == "trusted_file.txt"):
                            tkinter.messagebox.showinfo('Check File', 'It is a trusted file')
                          
                            flag = True
                            break
                    else: 
                        flag = False
                if(flag == False):
                    tkinter.messagebox.showerror('Check File', 'File not found')
        except:
            logging.exception("Exception in check hash")
