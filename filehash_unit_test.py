import hashlib
import unittest
from SimpleAntiVirus.filehash import HashFile

#filename must change according to the local machine
class TestFileHash(unittest.TestCase):
    file = HashFile()
    #Test CompareHash
    def test_comparehash(self):
        filename1="C:/Users/Davy/OneDrive/Desktop/S2_2023/COS20019/Assignment1b/all-subnet.png"

        file = HashFile()
        
        filename2="C:/Users/Davy/OneDrive/Desktop/S2_2023/COS20019/Assignment1b/all-subnet.png"
        sha256_output1 = file.hash_file(filename1, hashlib.sha256()) 
        md5_output1 = file.hash_file(filename1, hashlib.md5()) 
        sha1_output1 = file.hash_file(filename1, hashlib.sha1())

        sha256_output2 = file.hash_file(filename2, hashlib.sha256()) 
        md5_output2 = file.hash_file(filename2, hashlib.md5()) 
        sha1_output2 = file.hash_file(filename2, hashlib.sha1()) 

        self.assertTrue(file.CheckHash(sha256_output1, sha256_output2, md5_output1, md5_output2, sha1_output1, sha1_output2), True)
    
    #Test StoreFile malicious
    def test_store_maliciousfile(self):
        file = HashFile()
        filename1="C:/Users/Davy/OneDrive/Desktop/S2_2023/COS20019/Assignment1b/rt-table2.png"
        sha256_output1 = file.hash_file(filename1, hashlib.sha256()) 
       
        self.assertTrue(file.StoreFileFunction("SimpleAntiVirus/malicious_file.txt", sha256_output1), True)

    #Test StoreFile malicious
    def test_store_trustedfile(self):
        file = HashFile()
        filename1="C:/Users/Davy/OneDrive/Desktop/S2_2023/COS20019/Assignment1b/rt-table3.png"
        sha256_output1 = file.hash_file(filename1, hashlib.sha256()) 
       
        self.assertTrue(file.StoreFileFunction("SimpleAntiVirus/trusted_file.txt", sha256_output1), True)

    def test_checkfile(self):
        file = HashFile()
        file_checked="C:/Users/Davy/OneDrive/Desktop/S2_2023/COS20019/Assignment1b/BastionInstance.png"
        fileName1 = 'SimpleAntiVirus/malicious_file.txt'
        fileName2 = 'SimpleAntiVirus/trusted_file.txt'
        sha256_output1 = file.hash_file(file_checked, hashlib.sha256()) 
       
        self.assertTrue(file.CheckFileFunction(fileName1, fileName2, sha256_output1), True)

if __name__ == '__main__':
    unittest.main()