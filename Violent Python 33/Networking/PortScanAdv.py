'''
Created on Mar 6, 2013

@author: NNRooth
'''

## First Party Imports

## Third Party Imports
import pygeoip
import nmap
import FileIO.SaveFile

## Specific Imports
from time import clock
from sys import stdout
from socket import *
from threading import Semaphore
from threading import Thread

scan_list = []

thread_lock = Semaphore(value=1)
gi = pygeoip.GeoIP('../GeoDat/Geo.dat')

def getGeoLoc(host):
    try:
        rec = gi.record_by_name(host)
        city = rec['city']
        state = rec['region_name']
        country = rec['country_name']
        longitude = rec['longitude']
        latitude = rec['latitude']
        
        if city != '' and state != '':
            geoLoc = '%s,%s,%s : %6f,%6f' % (city, state, country, longitude, latitude)
        elif city != '':
            geoLoc = '%s,%s : %6f,%6f' % (city, country, longitude, latitude)
        else:
            geoLoc = '%s : %6f,%6f' % (country, longitude, latitude)
    except:
        geoLoc = 'Unregistered'
    finally:
        return geoLoc

def knockPort(host, port):
    try:
        nmScan = nmap.PortScannerAsync()
        nmScan.scan(host, port)
        state = nmScan[host]['tcp'][port]['state']
        geoLoc = getGeoLoc(host)
        ## Print Response
        thread_lock.acquire()
        scan_list.append('\n%s : %s : %s : %s' % (host, port, state, geoLoc))
        stdout.write('\n[+] %s#%s : %s : %s' % (host, port, state, geoLoc))
        thread_lock.release()
    except Exception as e:
        stdout.write('\n[-] Err: %s' % e)

def saveList2Log():
    ## check for empty list
    if not scan_list:
        return
    
    ## Get contents of scan_list
    logDoc = '' 
    for line in scan_list:
        logDoc += line.strip() + '\n'
    
    ## Check directory
    log_path = '../Logs/'
    FileIO.SaveFile.checkDir(log_path)
    
    ## Check file
    log_prefix = 'scan'
    log_extension = 'log'
    log_name = FileIO.SaveFile.checkFile(log_path, log_prefix, log_extension)
    
    ## Write to file
    try:
        FileIO.SaveFile.writeFile(log_path, log_name, logDoc)
        stdout.write('\n[+] Saved: %s' % log_name)
    except Exception as e:
        stdout.write('\n[-] Err: %s' % e)
    
def saveList2GoogleMap():
    ## Check for empy scan_list
    if not scan_list:
        return
    ## Init kml header & footer
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\
        \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>'
    kmlfooter = '\n</Document>\n</kml>'
    ## Create kml points
    kmlpts = ''
    for line in scan_list:
        info = line.split(':')
        if info[3].strip() == 'Unregistered':
            break
        host = info[0].strip()
        port = info[1].strip()
        coordinates = info[4].strip()
        kml = (
            '\n<Placemark>'
            '<name>%s:%s</name>'
            '<Point>'
            '<coordinates>%s</coordinates>'
            '</Point>'
            '</Placemark>'
            ) % (host, port, coordinates)
        kmlpts += kml
    
    ## Write kml file
    kmldoc = kmlheader + kmlpts + kmlfooter
    ## Check directory
    kml_path = '../KML/'
    FileIO.SaveFile.checkDir(kml_path)
        
    ## Check file
    kml_prefix = 'scan'
    kml_extension = 'kml'
    kml_name = FileIO.SaveFile.checkFile(kml_path, kml_prefix, kml_extension)
    
    ## Write to file
    try:
        FileIO.SaveFile.writeFile(kml_path, kml_name, kmldoc)
        stdout.write('\n[+] Saved: %s' % kml_name)
    except Exception as e:
        stdout.write('\n[-] Err: %s' % e)

def parseOctetRanges(toParse):
    parseMe = toParse.split('.')
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

def parsePortRanges(toParse):
    parseMe = toParse.split(',')
    ports = []
    for port in parseMe:
        ports.append(port.strip())
    return ports

def parseTime(time):
    hours = time / 60 / 24
    minutes = time /60 % 60
    seconds = time % 60
    return '%d hr : %d min : %d sec' % (hours, minutes, seconds)

def main():
    stdout.write('||---------------------||')
    stdout.write('\n||Port Scanner Advanced||')
    stdout.write('\n||---------------------||\n\n')
    user_octets = input('Hosts2Scan: ')
    user_ports = input('Ports2Scan: ')
    user_listen_timeout = float(input('Listen Timeout: '))
    user_thread_timeout = float(input('Thread Timeout: '))
    
    octet_ranges = parseOctetRanges(user_octets)
    setdefaulttimeout(user_listen_timeout)

    ## Octet Ranges
    octet_1_range = [octet_ranges[0],octet_ranges[1]]; octet_2_range = [octet_ranges[2],octet_ranges[3]]
    octet_3_range = [octet_ranges[4],octet_ranges[5]]; octet_4_range = [octet_ranges[6],octet_ranges[7]]
    ## Port Ranges
    ports = parsePortRanges(user_ports)
    
    scan_count = (octet_1_range[1] - octet_1_range[0]) * (octet_2_range[1] - octet_2_range[0]) * \
        (octet_3_range[1] - octet_3_range[0]) * (octet_4_range[1] - octet_4_range[0]) * len(ports) 
    
    stdout.write('\n[+] Scan Count: %s' % scan_count)
    input("\nPress Enter to continue...")
    stdout.write('\n[**] Starting Scan')
    start_time = clock()
    for octet_1 in range(octet_1_range[0], octet_1_range[1]):
        for octet_2 in range(octet_2_range[0], octet_2_range[1]):
            for octet_3 in range(octet_3_range[0], octet_3_range[1]):
                thread_lock.acquire()
                stdout.write('\n\n[*] Scanning: %s.%s.%s.*' % (octet_1, octet_2, octet_3))
                threads = []
                thread_lock.release()
                for octet_4 in range(octet_4_range[0], octet_4_range[1]):
                    host = '%s.%s.%s.%s' % (octet_1, octet_2, octet_3, octet_4)
                    for port in ports:
                        t = Thread(target=knockPort, args=(host, port))
                        threads.append(t)
                [x.start() for x in threads]
                [x.join(user_thread_timeout) for x in threads]
    
    stop_time = clock()
    elapsed_time = stop_time - start_time
    formatted_time = parseTime(elapsed_time)
    count = len(scan_list)
    saveList2Log()
    saveList2GoogleMap()
    stdout.write('\n\n[+] Run Time: %s' % formatted_time)
    stdout.write('\n[+] %s Open Ports Found' % count)
    stdout.write('\n[++] Scan Completed')

if __name__=='__main__':
    main()

