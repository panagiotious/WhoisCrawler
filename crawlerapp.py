## To change this license header, choose License Headers in Project Properties.
## To change this template file, choose Tools | Templates
## and open the template in the editor.

import socket
import subprocess
import radix
import time
import urllib2
from time import strftime, gmtime
import os
from netaddr import *
import sys, hashlib, sha3
import threading
import cPickle as pickle

import glob

class Master:
    def __init__(self):
        self.totalQueries = 0
        self.totalQueriesPerHour = 0
        self.cidrsFound = 0
        self.subprocessesComplete = 0
        self.timeFrame = 600
        
        self.numOfSubProcesses = 10
        self.iter = 0
        self.bogonsHash = "NA"          # bogons hash to verify updates #
        self.bogons = radix.Radix()
        
        # Server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverAddr = ('localhost', 6667)
        
        # Get the Cymru full bogons file:
        self.refreshBogons()
        pickle.dump(self.bogons, open('bogons.p', 'wb'))
        
        # Hash variables to check for differences in CIDRS files
        self.CIDRFormerHash = ''
        
        # Subprocesses
        self.subprocess = [\
        '0.0.0.0',
        '15.0.0.0',
        '30.0.0.0',
        '45.0.0.0',
        '70.0.0.0',
        '100.0.0.0',
        '125.0.0.0',
        '150.0.0.0',
        '168.0.0.0',    # was 175
        '200.0.0.0',
        '255.0.0.0']
        
        crawlersManagerThread = threading.Thread(target=self.crawlersManager)
        crawlersManagerThread.start()
        crawlersManagerThread.join()
        
        
    def crawlersManager(self):
        
        successfullyCrawled = 0
        
	self.log('notice', 'Crawlers Master Started')
        subprocessIPs = []
        subprocessIPs = list(self.subprocess)
        for i in xrange(10):
                subprocess.Popen('python crawl.py '+str(i)+' '+str(subprocessIPs[i])+' '+str(self.subprocess[i+1]+' '+str(self.timeFrame)), shell=True)

        self.sock.bind(self.serverAddr)
        self.sock.listen(1)
        while True:
            connection, client_address = self.sock.accept()
            try:
                while True:
                    data = connection.recv(1024)
                    if data:
                        # DO SOMETHING WITH THE DATA RECEIVED
                        dataArray = data.split('#')
                        if len(dataArray)==4:
                            subprocessIPs[int(dataArray[0])] = dataArray[1]    # the IP from which the next thread should start
                            self.subprocessesComplete += 1
                            self.totalQueries += int(dataArray[2])
                            self.totalQueriesPerHour += int(dataArray[2])
                            self.cidrsFound += int(dataArray[3])
                        else:
                            print "ERROR"
                    else:
                        break
            finally:
                connection.close()
                # If all subprocesses complete
                if self.subprocessesComplete == self.numOfSubProcesses:
                    self.subprocessesComplete = 0   # reset the counter
                    ''' LOG '''
                    self.log('bench', 'Total queries: '+str(self.totalQueries))
                    self.log('bench', 'Queries in the past hour: '+str(self.totalQueriesPerHour))
                    self.log('bench', 'Total CIDRs found: '+str(self.cidrsFound))
                    
                    ''' CREATE THE PICKLE '''
                    # invoke self.pickleManager()
                    pickleManagerThread = threading.Thread(target=self.pickleManager, args=[self.iter, subprocessIPs])
                    pickleManagerThread.start()
                    
                    ''' UPDATE BOGONS '''
                    if self.iter % 4 == 0:
                        self.refreshBogons()
                    
                    ''' RESTART THE SUBPROCESSES '''
                    self.totalQueriesPerHour = 0
                    restartedProcesses = 0
                    for i in xrange(10):
                        if not subprocessIPs[i] == '0':
                            restartedProcesses += 1
                            subprocess.Popen('python crawl.py '+str(i)+' '+str(subprocessIPs[i])+' '+str(self.subprocess[i+1])+' '+str(self.timeFrame), shell=True)
                            self.log('warning', 'MasterCrawler::crawlersManager('+str(self.iter)+'): Subrocces '+str(i)+' restarted.')
                    
                    self.iter += 1  # increase the current iteration iterator
                    self.numOfSubProcesses = restartedProcesses
                    
                    if restartedProcesses == 0:
                        self.log('warning', 'MasterCrawler::crawlersManager('+str(self.iter)+'): PROCESS COMPLETE.\n\n\n\n\n')
                        
                        self.mergeIndividualPickles()
                        
                        self.numOfSubProcesses = 10
                        self.totalQueries = 0
                        self.cidrsFound = 0
                        self.iter = 0
                        
                        successfullyCrawled += 1
                        for i in xrange(10):
                            subprocess.Popen('python crawl.py '+str(i)+' '+str(self.subprocess[i])+' '+str(self.subprocess[i+1]+' '+str(self.timeFrame)), shell=True)
                    

    def pickleManager(self, iterator, subprocessIPs):
        try:
            self.log('notice', 'MasterCrawler::pickleManager('+str(iterator)+'): Pickling process started.')
            pickles = []
            tree = radix.Radix()
            queue = []

            # Read the pickles and remove the old files:
            for indTree in glob.glob('cidrs_?'):
                temp = pickle.load(open(indTree, 'rb'))
                for n in temp:
                    node = tree.add(n.prefix)
                    node.data['asn'] = n.data['asn']
                    node.data['cc'] = n.data['cc']
                    node.data['reg'] = n.data['reg']
                    node.data['isp'] = n.data['isp']
                os.remove(indTree)
            
            for indQueue in glob.glob('queue_?'):
                queue += pickle.load(open(indQueue, 'rb'))
                os.remove(indQueue)
            
            self.log('notice', 'MasterCrawler::pickleManager('+str(iterator)+'): Individual pickles collected. Files removed.')
            # Pickle the hourly tree and queue:
            pickle.dump(tree, open('tree_state_'+str(iterator), 'wb'))
            pickle.dump(queue, open('queue_state_'+str(iterator), 'wb'))
            
            self.log('notice', 'MasterCrawler::pickleManager('+str(iterator)+'): Pickling process complete. Files tree_state_'+str(iterator)+' and queue_state_'+str(iterator)+' created successfully.')
        except Exception as e:
            self.log('error', 'MasterCrawler::pickleManager('+str(iterator)+'): An unexpected error occured: '+str(e))
        self.log('notice', 'MasterCrawler::pickleManager('+str(iterator)+'): Pickle manager out!')
        
    
    def mergeIndividualPickles(self):
        self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): Collecting data...')
        tree = radix.Radix()
        temp = radix.Radix()
        queue = []
        cidrFilesMerged = 0
        queueFilesMerged = 0
        
        # Get all tree_states created:
        for indTree in glob.glob('tree_state_*'):
            temp = pickle.load(open(indTree, 'rb'))
            for node in temp:
                n = tree.add(node.prefix)
                n.data['asn'] = node.data['asn']
                n.data['cc'] = node.data['cc']
                n.data['reg'] = node.data['reg']
                n.data['isp'] = node.data['isp']
            os.remove(indTree)
            cidrFilesMerged += 1
        for indQueue in glob.glob('queue_state_*'):
            queue += pickle.load(open(indQueue, 'rb'))
            os.remove(indQueue)
            queueFilesMerged += 1
        self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): Data collected. Saving...')
        
        '''
        CHECK IF ANYTHING HAS CHANGED AND ARCHIVE THE OLD CIDR
        '''
        # Generate the tree digest:
        h = hashlib.sha3_256()
        h.update(pickle.dumps(tree))
        
        # Check if something has changed:
        if not h.hexdigest() == self.CIDRFormerHash:
            self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): A difference was spotted in the tree.')
            # Archive the old CIDR if exists
            oldCidrFilename = glob.glob('CIDR*')    # get the CIDRS filename
            if len(oldCidrFilename) == 1:   # if an older CIDRS file exists
                self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): Archiving old CIDRS file.')
                filename = oldCidrFilename[0]
                os.rename(filename, 'ARCHIVE_'+filename[6:])    # rename the old file to ARCHIVE_$DATE$
                # Store the big tree and queue:
                pickle.dump(tree, open('CIDRS.'+strftime("%Y%m%d%H%M", gmtime()), 'wb'))
                pickle.dump(queue, open('QUEUE.'+strftime("%Y%m%d%H%M", gmtime()), 'wb'))
            elif len(oldCidrFilename) > 1:
                self.log('error', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): More than one CIDRS files found!')
            else:
                self.log('error', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): No former CIDRS file found. Please verify that this is correct.')
                # Just overwrite
                pickle.dump(tree, open('CIDRS.'+strftime("%Y%m%d%H%M", gmtime()), 'wb'))
                pickle.dump(queue, open('QUEUE.'+strftime("%Y%m%d%H%M", gmtime()), 'wb'))
        else:
            self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): Trees are the same.')
            # If the checksums are the same just update the date/time
            oldCidrFilename = glob.glob('CIDR*')
            if len(oldCidrFilename) == 1:
                self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): Updating the CIDRS file name.')
                filename = oldCidrFilename[0]
                os.rename(filename, filename[:7]+strftime("%Y%m%d%H%M", gmtime()))  # rename the old file with the current date/time
            else:
                self.log('error', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): No former CIDRS file found. Please verify that this is correct.')
                # Just overwrite
                pickle.dump(tree, open('CIDRS.'+strftime("%Y%m%d%H%M", gmtime()), 'wb'))
                pickle.dump(queue, open('QUEUE.'+strftime("%Y%m%d%H%M", gmtime()), 'wb'))
        
        self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): CIDRS.p and QUEUE.p created.')
        self.log('notice', 'MasterCrawler::mergeIndividualPickles('+str(self.iter)+'): '+str(cidrFilesMerged)+' individual CIDR and '+str(queueFilesMerged)+' Queue files merged.')
    
    def refreshBogons(self):
        self.log('notice', 'MasterCrawler::refreshBogons('+str(self.iter)+'): Attempting to update bogons list.')
        try:
            bogonsList = urllib2.urlopen('http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt').read().splitlines()
            bogonsList.remove(bogonsList[0])
            # In case the bogons file is different update the bogons tree:
            if self.bogonsHasChanged(''.join(bogonsList)):  # reconstruct the list to a string to hash
                for bog in bogonsList:
                    node = self.bogons.add(str(IPNetwork(bog)))
                    node.data['fin'] = str(IPNetwork(bog)[-1])
                pickle.dump(self.bogons, open('bogons.p', 'wb'))
                self.log('notice', 'MasterCrawler::refreshBogons('+str(self.iter)+'): Bogons list has been updated successfully.')
            self.log('warning', 'MasterCrawler::refreshBogons('+str(self.iter)+'): Bogons list has not changed.')
        except Exception as e:
            self.log('error', 'MasterCrawler::refreshBogons('+str(self.iter)+'): Failed to update bogons list: '+str(e))
    
    # Used to check if the bogons file has been updated (with SHA3-256):
    def bogonsHasChanged(self, newFile):
        if sys.version_info<(3,4):
            import sha3
            hf = hashlib.sha3_256()
            hf.update(newFile)
            if hf.hexdigest() == self.bogonsHash:
                return False
            self.bogonsHash = hf.hexdigest()
            return True
            
    # Logging method:
    def log(self, type, data):
        logFile = open('logfile.log', 'a')
        if type == 'error':
            logFile.write(strftime("%Y-%m-%d %H:%M:%S", gmtime())+" GMT ["+str(os.getpid())+"]<Error>: "+data+"\n")
        elif type == 'notice':
            logFile.write(strftime("%Y-%m-%d %H:%M:%S", gmtime())+" GMT ["+str(os.getpid())+"]<Notice>: "+data+"\n")
        elif type == 'warning':
            logFile.write(strftime("%Y-%m-%d %H:%M:%S", gmtime())+" GMT ["+str(os.getpid())+"]<Warning>: "+data+"\n")
        elif type == 'bench':
            logFile.write(strftime("%Y-%m-%d %H:%M:%S", gmtime())+" GMT ["+str(os.getpid())+"]<Benchmark>: "+data+"\n")
        logFile.close()
    
if __name__ == "__main__":
    Master()
