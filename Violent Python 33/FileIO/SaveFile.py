'''
Created on Mar 5, 2013

@author: NNRooth
'''

## First Party Imports

## Third Party Imports

## Specific Imports
from os import path
from os import makedirs
from sys import stdout

def checkDir(directory):
    if not (path.exists(directory)):
        try:
            makedirs(directory)
        except Exception as e:
            stdout.write('\n[-] Err: %s' % e)
            return

def checkFile(file_path, file_prefix, file_extension):
    file_suffix = 0
    file_name = '%s-%d.%s' % (file_prefix, file_suffix, file_extension)
    while (path.exists('%s%s' % (file_path, file_name))):
        file_suffix += 1
        file_name = '%s-%d.%s' % (file_prefix, file_suffix, file_extension)
    return file_name

def writeFile(file_path, file_name, data):
    f = open('%s%s' % (file_path, file_name), 'w+')
    f.write(data)
    f.close()

def main():
    stdout.write('Save File')

if __name__ == '__main__':
    main()