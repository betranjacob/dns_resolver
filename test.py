#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep
import sys

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *
from twisted.internet.test.test_tcp import DataReceivedRaisingClient
from gtk import TRUE

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"
UDP_PORT = 53
HEADER_SIZE = 12


class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
   self._srtt = srtt
   self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
     
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)




# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialise the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([ (DomainName("."), OrderedDict([(DomainName(ROOTNS_DN), CacheEntry(expiration=MAXINT, authoritative=True))]) )])

# Initialise the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))]) 

cnamecache_current = dict([])
cnamecache = dict()

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value


parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()


# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
#ss.bind(("127.0.0.1", options.port))
ss.bind(("127.0.0.1", 8889))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

def func_name():
    import traceback
    return traceback.extract_stack(None, 2)[0][2]
# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (rq_data, address,) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not rq_data:
    log.error("client provided no data")
    continue


  offset = 0 # Initialise offset for data parsing
  
  #header = Header.fromData(rq_data, offset)
  offset += HEADER_SIZE # Increment offset to header size
  requestQuery = QE.fromData(rq_data, offset)

  iq_data = rq_data # Copying the query from client
  shouldContinue = True # Flag to iterate until we get a valid answer

  ns_to_query = ROOTNS_IN_ADDR # Start querying from a Root Name server 
  
  
  while shouldContinue == True:
    

    ir_header = Header.fromData(iq_data, 0)
    print "Received Header from root server  ", ir_header
    
    myQE = QE.fromData(iq_data, 12)
    print "Query ", myQE
    
    #sys.stdin.read(1)
    cs.sendto(iq_data, (ns_to_query, UDP_PORT))
    (ir_data, ir_address,) = cs.recvfrom(512)
    
    offset = 0 # Initialise offset for data parsing


    ir_header = Header.fromData(ir_data, offset)
    #print "Received Header from root server  ", ir_header
    offset += HEADER_SIZE
    
    total_number_of_records = ir_header._ancount + ir_header._nscount + ir_header._arcount
    #print "Total Records in response ",  total_number_of_records
    myQE = QE.fromData(ir_data, offset) 
    
    print myQE
    
    query_size = len(myQE); # FIXME: Assuming one query

    offset += query_size
    print "Query in Response ", myQE

    rr_count = 0 # Variable to iterate through Resource records
    print " Answer Count ", ir_header._ancount, " NS count ", ir_header._nscount, " Additional Records count ", ir_header._arcount, "Total Records", total_number_of_records

    while rr_count < total_number_of_records:
        resource_record, record_length = RR.fromData(ir_data, offset)
        
        print "Total", total_number_of_records, "rr_count ", rr_count, "Length  ", record_length,  resource_record
              
        offset += record_length # Advance the read offset
        rr_count += 1 # Increment Resource record count       
   
    print "Responding to Client >>> "
    ss.sendto(ir_data, address)
    