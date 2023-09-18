import hashlib
import os

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

    def hash_file(self):
        hash_obj = hashlib.sha256()
        with open(self.fileName, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def CheckHash(self, output1, output2):
        if(output1 == output2):
            print("Both Hash is the same", output1, output2)
            return True
        else:
            print("Different Hash")
            return False

    def StoreFile(self, fileName, text):
        flag = False
        with open(fileName, "a+") as file:
            if(os.stat(fileName).st_size == 0):
                file.write(text)
                file.write("\n")
                print("File is stored")
            else:
                with open(fileName, "r") as file1:
                    Lines = file1.readlines()
                    for line in Lines:
                        if(text == line.strip()):
                            print("File existed")
                            flag = False
                            break
                        else:
                            flag = True
                    if(flag == True):
                        file.write(text)
                        file.write("\n")
                        print("File is stored")

    def CheckFile(self, fileName, text):
        flag = False
        output = ''
        with open(fileName, "r") as file1:
            Lines = file1.readlines()
            for line in Lines:
                print(line)
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
                print("File not found")
            else:
                print(output)
