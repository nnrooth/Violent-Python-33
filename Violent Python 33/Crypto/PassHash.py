'''
Created on Mar 20, 2013

@author: NNRooth
'''

import crypt

def main():
    salt = crypt.mksalt(crypt.METHOD_SHA256)
    crypt.crypt("hOk11Q3r", salt)

if __name__ == '__main__':
    main()