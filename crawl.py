# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.

import sys
import time
import radix

from netaddr import *
from time import strftime, gmtime
import os
import subprocess
import cPickle as pickle

import socket
import urllib2
import sys, hashlib
'''
argv[0]: file name
argv[1]: thread name
argv[2]: starting IP
argv[3]: last IP
argv[4]: time to run

'''

class Crawl:
    def __init__(self):

        self.processName = sys.argv[1]
        self.firstIp = IPAddress(sys.argv[2])
        self.lastIp = IPAddress(sys.argv[3])
        self.timeLimit = float(sys.argv[4])
        
        self.startTime = time.time()
        self.currentTime = time.time()
        self.bogons = radix.Radix()
        self.cidrs = radix.Radix()
        self.naCidrs = []
        
        self.totalQueries = 0
        self.totalQueriesPerHour = 0
        self.cidrsFound = 0
        
        self.bogons = pickle.load( open( "bogons.p", "rb" ) )
        self.start()
        
    def start(self):
        ip = self.firstIp
        self.log('notice', 'Worker('+self.processName+')::start(): Started crawling from '+str(ip)+ ' to '+str(self.lastIp)+' for '+str(self.timeLimit/60)+' minutes.')
        while (float(self.currentTime - self.startTime) < self.timeLimit) and (ip < self.lastIp):
            try:
                node = self.bogons.search_best(str(ip))
                if node:
                    self.log('warning', 'Worker('+self.processName+')::start(): Skipping bogon IP '+str(ip))
                    if str(node.data['fin']) == '255.255.255.255':
                        ip = IPAddress('255.255.255.255')
                    else:
                        ip = IPAddress(node.data['fin']) + 1
                else:
                    answer_list = self.dnsQuery(str(ip))
                    if(str(answer_list[0])=="NA"):
                        self.naCidrs.append(str(ip+1))
                        ip = IPAddress(str(IPNetwork('::'+str(ip)+'/120')[-1]).strip('::')) + 1
                    elif(str(answer_list[0])=="No response"):
                        raise Exception("Time out for IP: "+str(ip)+".")
                    else:
                        self.cidrsFound = self.cidrsFound + 1
                        if(len(str(answer_list[0]).split('/'))>1):
                            leaf = self.cidrs.add(str(answer_list[0]))
                            leaf.data['asn'] = str(answer_list[1])
                            leaf.data['cc'] = str(answer_list[2])
                            leaf.data['reg'] = str(answer_list[3])
                            leaf.data['isp'] = str(answer_list[4])
                            cidr_ip = IPNetwork(answer_list[0])
                            ip = cidr_ip.ip + cidr_ip.size
                        else:
                            self.log('error', 'Worker('+self.processName+')::start(): Unexpected error (else)')
                            ip = ip + 1
            except Exception as e:
                self.log('error', 'Worker('+self.processName+')::start(): Failed to query server: '+str(e))
                self.log('error', 'Worker('+self.processName+')::start(): Suspending for 10 seconds.')
                time.sleep(10)
            self.currentTime = time.time()  # update the current time
        
        if (ip >= self.lastIp):
            self.log('notice', 'Worker('+self.processName+')::start(): Completed crawling my range.')
        else:
            self.log('notice', 'Worker('+self.processName+')::start(): Finished crawling after '+str(self.timeLimit/60)+' minutes.')
        
        time.sleep(5)    
        self.createPickles()
        self.contactMaster(ip)


    def dnsQuery(self,ip):
        self.totalQueries = self.totalQueries + 1
        self.totalQueriesPerHour = self.totalQueriesPerHour + 1
	IP_reversed = self.reverseIP(str(ip))
	querycmd1 = IP_reversed + '.origin.asn.cymru.com'
	response1 = subprocess.Popen(['dig', '-t', 'TXT', querycmd1, '+short'],stdout=subprocess.PIPE).communicate()[0]
        response1List = response1.split('|')
        # Check if the server timed out and return 'No response' in list[0]
        if response1.startswith('\n; <<>> DiG'):
            return ["No response", "NA", "NA", "NA", "NA"]
	ASN = response1List[0].strip('" ')
        ISP = self.ansnum2isp(ASN)
	if(ISP != "error"):
            Network = response1List[1].strip()
            Country = response1List[2].strip()
            Registry = response1List[3].strip()
            return [Network, ASN, Country, Registry, ISP]
	else:
            return ["NA", "NA", "NA", "NA", "NA"]
	return answer_list
    
    def reverseIP(self,address):
 	temp = address.split(".")
	convertedAddress = str(temp[3]) +'.' + str(temp[2]) + '.' + str(temp[1]) +'.' + str(temp[0])
    	return convertedAddress
    
    def ansnum2isp(self,ASN):
	querycmd2 = 'AS' + ASN + '.asn.cymru.com'
	response2 = subprocess.Popen(['dig', '-t', 'TXT', querycmd2, '+short'], stdout=subprocess.PIPE).communicate()[0]
	response2List = response2.split('|')
	if (len(response2List) < 4):
		return "error"
        ISP = response2List[4].replace('"', '')
        return ISP   
    
    def createPickles(self):
        try:
            self.log('notice', 'Worker('+self.processName+')::createPickles(): Creating CIDRS pickle file cidrs_'+str(self.processName)+'.')
            pickle.dump(self.cidrs, open('cidrs_'+str(self.processName), 'wb'))
            self.log('notice', 'Worker('+self.processName+')::createPickles(): Creating Queue pickle file queue_'+str(self.processName)+'.')
            pickle.dump(self.naCidrs, open('queue_'+str(self.processName), 'wb'))
        except Exception as e:
            self.log('error', 'Worker('+self.processName+')::createPickles(): Could not create pickles. Exited with error: '+str(e))
            
    
    # Will send process_name#0#total_queries#cidrs_found if the process is complete, or process_name#current_ip#number_of_queries#cidrs_found
    def contactMaster(self, ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverAddr = ('localhost', 6667)
        try:
            sock.connect(serverAddr)
            if not ip < self.lastIp:    # if the process completed crawling
                message = str(self.processName)+'#0#'+str(self.totalQueries)+'#'+str(self.cidrsFound)
            else:
                message = str(self.processName)+'#'+str(ip)+'#'+str(self.totalQueries)+'#'+str(self.cidrsFound)
            sock.sendall(message)
        except Exception as e:
            self.log('error', 'Worker('+self.processName+')::createPickles(): Failed to contact master: '+str(e))
        finally:
            sock.close()
                
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
    Crawl()
