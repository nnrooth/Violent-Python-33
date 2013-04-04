'''
Created on Mar 13, 2013

@author: NNRooth
'''

# Library Imports
import nmap
from threading import Thread
from threading import Semaphore
from time import clock

# Threading Lock
thread_lock = Semaphore(value=1)

def nmapScan(tgtHost, tgtPort):
    try:
        nmScan = nmap.PortScanner()
        nmScan.scan(tgtHost, tgtPort)
        state=nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
        if state == 'closed':
            pass
        else:
            thread_lock.acquire()
            print('[*] %s tcp/%s %s' % (tgtHost, tgtPort, state))
    except:
        pass
    finally:
        thread_lock.release()

def parseTime(time):
    hours = time / 60 / 24
    minutes = time /60 % 60
    seconds = time % 60
    return '%d hr : %d min : %d sec' % (hours, minutes, seconds)

def parseOctetRanges(octet_ranges):
    parseMe = octet_ranges.split('.')
    octets = []
    for octet in parseMe:
        octet = octet.strip()
        if octet == '*':
            octets.append(1); octets.append(256)
        elif '-' in octet:
            limits = octet.split('-')
            octets.append(int(limits[0])); octets.append(int(limits[1])+1)
        else:
            octets.append(int(octet)); octets.append(int(octet)+1)
    return octets

def main():
    print('[+] Python Nmap Scanner')
    tgtHost = input('[.] Host: ')
    tgtPorts = input('[.] Ports: ')
    
    # Find port range
    if tgtPorts == '*':
        tgtPorts = ['20','21','22','23','25','43','53','80','110','143','443','464','1080','1194','1900','4444','9988']
    else:
        tgtPorts = tgtPorts.split(',')
        
    # Start Timer
    start_time = clock()
    print('[*] Scanning: %s' % tgtHost)
    
    # Created thread array
    thread_group = []
    for tgtPort in tgtPorts:
        t = Thread(target=nmapScan, args=(tgtHost, tgtPort.strip()))
        thread_group.append(t)
    
    # Start and join threads in array
    [x.start() for x in thread_group]
    [x.join(10) for x in thread_group]

    # Stop Timer
    end_time = clock()
    elapsed_time = end_time - start_time
    formatted_time = parseTime(elapsed_time)
    
    # Print Timer Results
    print('[+] Scan Completed in %s' % formatted_time)
    
if __name__ == '__main__':
    main()