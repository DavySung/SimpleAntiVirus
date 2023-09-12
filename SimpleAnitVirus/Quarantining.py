import os

def Main():

    dir_name = "quarantine"
    aPath = input("Please enter file location address (including file extension): ")
    aPath = aPath.rsplit("\", 1)
    filedir = aPath[0]
    filename = aPath[1]
    print(filedir + filename)
    #quarantine(aPath)

    # #Delete or restore file
    # choice = input("Would you like to (D)elete or (R)estore?: ")

    # if choice == 'D':
        # file_path = #Read file path from text file
        # os.remove(file_path)

    # elif choice == 'R':
        # with open('quar_id.txt') as f:
            # quar_id = f.readline()
        # restore_from_quar(quar_id)
        # print ("Done.")

    # else: 
        # print ("No valid option selected, closing...")
        
# def quarantine(pPath):

    # f = open('quar_id.txt','w')
    # f.write(pPath)
    # f.close()
    # #os.chdir(dir_name)
    # shutil.move(pPath,dir_name+'/'+file)
    
# def restore(quar_id):

    # os.chdir(dir_name)
    # myfile = os.listdir(dir_name)
    # file = str(myfile)
    # file = file[2:-2]
    # shutil.quarantine(file,quar_id+'/'+file)

    # #Change permissions
    # os.chmod(r'C:\Users\p\Documents\program\sample.txt', 0o777)
    # print('file can be read, write and execute for owner, group and others')

    # os.chmod(r'C:\Users\p\Documents\program\sample.txt', 0o400)
    # print('file can be read only for owner')

    # os.chmod(r'C:\Users\p\Documents\program\sample.txt', 0o600)
    # print('file can be read and write only for owner')