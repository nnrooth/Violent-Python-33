'''
Created on Mar 20, 2013

@author: NNRooth
'''

import zipfile
from sys import stdout
from threading import Thread
from threading import Semaphore

threadLock = Semaphore(value=1)

def extractZip(zipFile, password):
    try:
        zipFile.extractall(pwd=password)
        stdout.write('[+] Pass : %s' % password.decode())
        Thread._stop()
    except:
        pass

def decryptZip(zipfilename, dicfilename):
    zFile = zipfile.ZipFile(zipfilename)
    pFile = open(dicfilename)
    
    maxThreads = 30
    threadCount = 0
    for line in pFile.readlines():
        password = line.strip().encode('utf-8', 'strict')
        s = line.strip()
        stdout.write(":".join("{0:x}".format(ord(c)) for c in s))
        stdout.write('\t%s\n' % password)
        t = Thread(target=extractZip, args=(zFile, password))
        threadCount += 1
        if (threadCount >= maxThreads):
            threadCount = 0
            t.start()
    t.start()
        
    return None

def main():
##    stdout.write('[+] Zip Nasty!!!\n')
    
##    zipfilename = input('[.] Zip File Path: ')
##    dicfilename = input('[.] Dic File Path: ')
    zipfilename = '../zipTest/pass.zip'
    dicfilename = '../zipTest/pass.dic'    
    if not (zipfile.is_zipfile(zipfilename)):
        stdout.write('[-] %s is not a zip file...\n' % zipfilename)
        exit(0)
    else:
        stdout.write('[*] Decrypting %s\n' % zipfilename)
    
    decryptZip(zipfilename, dicfilename)
##    stdout.write('[!] Done\n')

if __name__ == '__main__':
    main()