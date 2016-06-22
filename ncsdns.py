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

ROOTNS_IN_ADDR = "192.5.5.241"
ROOTNS_IN_ADDR1 = "192.58.128.30"

# domain name and internet address of a root name server
ROOTNS_DN = "m.root-servers.net."  

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


TYPE_CNAME = 1
TYPE_DN = 2

# A stack data structure to push/pop multilevel address resolution
class Stack:
      
  def __init__(self):
    self.items = dict()
    self.top = -1
    
  def push(self, item):
      #print "Pushing ", item, "to stack()"
      self.top += 1
      self.items[self.top] = item
  
  def pop(self):
      if self.top == -1:
        return 0  
      else:    
        item = self.items[self.top]
        #print "Popping ", item, "from stack()"
        del self.items[self.top]
        self.top -= 1
        return item
    
  def size(self):
      return len(self.items)       

  def isEmpty(self):      
      if len(self.items) == 0:
          return True;
      else:
          return False
    
address_resolution_stack = Stack()

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

# Function that prints the calling functions name, used for debugging purposes.
def func_name():
    import traceback
    return traceback.extract_stack(None, 2)[0][2]

# This function creates an DNS response packet with addresses and cname entries. 
# Ideally invoked, if we find a cache match of the query from client.
def append_cname_aliases_from_cache(ir_data, domain):
    
    rqHeader = Header.fromData(ir_data, 0)    
    myQE = QE.fromData(ir_data, HEADER_SIZE)
    
    rr_data = ir_data
    
    if cnamecache.has_key(domain):
        cname_cache_size = len(cnamecache[domain])
    
        rqHeader._ancount = cname_cache_size # Set the answer count to the number of CNAMEs            
        rqHeader._qr = 1 # This is a response      
        rqHeader._aa = 1 # This is a response      
        rqHeader._ra = 1 # recursion available
        rqHeader._nscount = 0 # no authoritative
        rqHeader._arcount = 0 # no additional 
    

        # Attach Header and Query
        rr_data = rqHeader.pack() + myQE.pack()
    
        dn_t = domain
    
        for i in range(0, cname_cache_size): # Browser through the entire cache within the domain
            cname = cnamecache[domain][dn_t][0] # Copy the cname (first element in list)from cache
            ttl = cnamecache[domain][dn_t][1]  # Copy the ttl (second element in list)from cache
            if i == cname_cache_size-1:        # Last entry is actual internet address
                ra = RR_A(dn_t, ttl, inet_aton(cname))
            else:
                ra = RR_CNAME(dn_t, ttl, cname)
            rr_data += ra.pack()
            #print ra
            dn_t = cname       
    else:
        print func_name() , domain, "is not available in cnamecache"
        print cnamecache
        
    return rr_data

# This function is used to respond to the current query with cname alias.
def append_cname_aliases_from_current_cache(ir_data, domain):
    
    rqHeader = Header.fromData(ir_data, 0)    
    myQE = QE.fromData(ir_data, HEADER_SIZE)
    
    cname_cache_size = len(cnamecache_current)
    rqHeader._ancount = cname_cache_size+1 
    rqHeader._ra = 1 # recursion available
    rqHeader._nscount = 0
    rqHeader._arcount = 0
    
    # Pop out the answer record, we have to append this at the end of the Answer section
    answer_record, record_length = RR.fromData(ir_data, HEADER_SIZE+len(myQE))   
    
    # Attach Header and Query
    rr_data = rqHeader.pack() + myQE.pack()
    
    dn_t = domain
     
    for i in range(0, cname_cache_size): 
        cname = cnamecache_current[dn_t][0]
        ttl = cnamecache_current[dn_t][1]     
        ra = RR_CNAME(dn_t, ttl, cname)    
        rr_data += ra.pack()
        dn_t = cname       
    
    answer_list = [inet_ntoa(answer_record._inaddr), answer_record._ttl] # List with cname resolution answer answer 
    cnamecache_current[answer_record._dn] = answer_list # This is stored in answer record domain name
    cnamecache[domain] = cnamecache_current.copy() # Now we copy temporary cname cache to global 
    
    # Finally append the Answer        
    rr_data += answer_record.pack() 
    
    '''
    total_number_of_records = rqHeader._ancount + rqHeader._nscount + rqHeader._arcount
    rr_count = 0       
    offset = HEADER_SIZE + len(myQE)
    while rr_count < total_number_of_records:
        answer_record, record_length = RR.fromData(rr_data, offset)
        print answer_record
        rr_count += 1
        offset += record_length
    '''
    return rr_data

# This function is used to create a  response with the given domain name.
# Ideally invoked after we have resolved the final answer and recreate the packet with original 
# query from client.    
def generate_response_with_dn(rq_data, dn, error):

    rqHeader = Header.fromData(ir_data, 0)   
    myQE = QE.fromData(ir_data, HEADER_SIZE)
    rqHeader._ra = 1;
    rqHeader._qr = 1;    
    
    if error == True:    
        rqHeader._ancount = 0
        rqHeader._arcount = 0
        rqHeader._nscount = 0   
        rqHeader._rcode = rqHeader.RCODE_NAMEERR;
        myQE._dn = DomainName(str(dn))
        rr_data = rqHeader.pack() + myQE.pack();
    else:
        resource_record, record_length = RR.fromData(rq_data, HEADER_SIZE+len(myQE))           
        myQE._dn = DomainName(str(dn)) 
        rr_data = rqHeader.pack() + myQE.pack() + resource_record.pack()
        
    return rr_data 

# Appends the packet with answer fields Domain name, Answer ip address and TTL.
def append_answer(rq_data, dn, iAddr, ttl):
        
    rqHeader = Header.fromData(rq_data, 0)
    myQE = QE.fromData(rq_data, HEADER_SIZE)  

    rqHeader._ancount = 1 # One answer
    rqHeader._qr = 1 # This is a response      
    rqHeader._ra = 1 # recursion available                       
    rqHeader._nscount = 0 # no authoritative
    rqHeader._arcount = 0 # no additional 
    
    if dn == 0:
        dn = myQE._dn    
    
    ra = RR_A(dn, ttl, inet_aton(iAddr))    
    rr_data = rqHeader.pack() + myQE.pack() + ra.pack() 
    
    return rr_data

# Appends the authoritative and associated glue record to a response packet.
# As per requirement it will append only one record.     
def append_athoritive_glue_records_from_cache(ir_data):
    
    rr_data = ir_data
    offset = 0
    myHeader = Header.fromData(ir_data, offset)
    
    if myHeader._nscount == 0:
        
        myHeader._ra = 1
        myHeader._nscount = 1
        myHeader._arcount = 1
        offset += HEADER_SIZE
        
        myQE = QE.fromData(ir_data, offset)
        domain = myQE._dn
        offset += len(myQE)
        
        #print "Answer Count", myHeader._ancount
        if domain.parent() in nscache:
                        
            rr_data = myHeader.pack() + myQE.pack()       
            an_count = 0
            
            while an_count < myHeader._ancount:                
                answer, answer_length = RR.fromData(ir_data, offset)
                rr_data  += answer.pack()
                offset   += answer_length
                an_count += 1
                #print  an_count, offset
            keys = nscache[domain.parent()].keys() # Get the keys from  answer's->parent domain  
            
            for i in range(0, len(nscache[domain.parent()])):       
                if keys[i] in acache.keys(): # Check if the first NS address is available in address cache 
                    iAddr = str(acache[keys[i]]._dict.keys()[0]) # Copy Address
                    ttl   = acache[keys[i]]._dict.values()[0]._expiration # Copy ttl
                
                    authoritative_record = RR_NS(domain.parent(), ttl, keys[i]) # Create at least 1 authoritive record as per requirement 
                    additional_record    =  RR_A(keys[i], ttl, inet_aton(iAddr))
                
                    rr_data += authoritative_record.pack()
                    rr_data += additional_record.pack()
                    break;
                #else:
                    #print "Sorry we can't find",  keys[i], "in address cache"    
                    #print acache.keys()
                    #print acache
    else:
        rr_data = ir_data
       
    return rr_data     

# Creates a query packet with the domain address supplied.
# Ideally invoked to create a custom query during a recursive resolution process.
def generate_query_packet_with_address(ir_data, domain):

    rqHeader = Header.fromData(ir_data, 0)
    
    rqHeader._ancount = 0 # No Answer
    rqHeader._arcount = 0 # No Authority
    rqHeader._nscount = 0 # No Name server
    
    myQE = QE.fromData(ir_data, HEADER_SIZE)
    myQE._dn = DomainName(str(domain)) 
    rr_data = rqHeader.pack() + myQE.pack()

    return rr_data #(rqHeader.pack() + myQE.pack())

# Clears entire caches and address resolutions stack.
def clear_all():
    
    while not address_resolution_stack.isEmpty():
            address_resolution_stack.pop()
            
    cnamecache_current.clear()          
    nscache_local.clear()
    acache_local.clear()     

# This function finds the next glue record from a given index.
# Ideally used to run through all the authoritative servers, if one server fails to resolve the address. 
def find_next_iAddr_from_domain(domain, sub_domain_query_index):   
        
    keys = nscache[domain].keys()
    iAddr = 0
    isSuccess = False
    
    if sub_domain_query_index < len(acache):         
        if keys[sub_domain_query_index] in acache.keys():           
            iAddr = str(acache[keys[sub_domain_query_index]]._dict.keys()[0])
            isSuccess = True
        #else:
        #    print func_name(), "sub_domain is not available ", keys[sub_domain_query_index]
    #else:
        #print "if sub_domain_query_index < len(acache)", sub_domain_query_index, len(acache)

    #print func_name(), isSuccess, iAddr        
    return isSuccess, iAddr

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (rq_data, address,) = ss.recvfrom(512) # DNS limits message to 2048 bytes
  if not rq_data:
    log.error("client provided no data")
    continue


  offset = 0 # Initialise offset for data parsing
  
  #header = Header.fromData(rq_data, offset)
  offset += HEADER_SIZE # Increment offset to header size
  requestQuery = QE.fromData(rq_data, offset)

  address_available_in_cache = False
  address_available_in_cname_cache = False
   
  rr_data = rq_data # Assigning Question to response
 
  # Check if the requested address is available in our address cache.
  if acache.has_key(requestQuery._dn):
      print "Address available in Cache >"  
      #print "## ADDRESS cache has the address ##"
      address_available_in_cache = True        
      for key1 , value1 in acache[requestQuery._dn]._dict.iteritems():            
        inet_address = key1
        ttl = value1._expiration
      rr_data = append_answer(rr_data, requestQuery._dn, str(inet_address), ttl)

                        
  if cnamecache.has_key(requestQuery._dn):
    #print "## CNAME cache has the address ##" 
    address_available_in_cname_cache = True

  iq_data = rq_data # Copying the query from client
  shouldContinue = True # Flag to iterate until we get a valid answer

  ns_to_query = ROOTNS_IN_ADDR # Start querying from a Root Name server 
  
  actual_query_address = 0 # Initialising query address, This is required to restore actual domain, once the recursive query has resolved all records 
  resolving_top_domain = False # A flag to indicate we are resolving a TLD of the actual answer
  resolving_cname_soa_domain = False # A flag to indicate we are resolving a cname
   
  cnamecache_current.clear()
  
  answer_available = False # We set this flag to False before running a query request
  cname_found = False # This flag is set to false and enabled accordingly if we find a cname Answer
  soa_found = False
  socket_timedout = False
  socket_retries = 0;
  
  while shouldContinue == True and not address_available_in_cache  and not address_available_in_cname_cache:
    
    answer_available = False # We set this flag to False before running a query request
    cname_found = False # This flag is set to false and enabled accordingly if we find a cname Answer
    soa_found = False
    
    ir_header = Header.fromData(iq_data, 0)
    #print "Received Header from root server  ", ir_header
    
    myQE = QE.fromData(iq_data, 12)
    
    cs.sendto(iq_data, (ns_to_query, UDP_PORT))
    try:
        (ir_data, ir_address,) = cs.recvfrom(2048)
    except timeout:
        socket_retries += 1
        if(socket_retries > 1):
            clear_all()
            socket_retries = 0
            socket_timedout = True
            break
        elif(socket_retries == 1):
            print "socket timeout, retrying..."
            ns_to_query = ROOTNS_IN_ADDR1
            continue
        

        
    nscache_local = dict() # Local Name server cache used to populate NS yielded for each query
    acache_local = dict() # Local Address  cache used to populate Internet addresses yielded for each query
     
    domain = 0 # "www.betranjacob.com"      
    offset = 0 # Initialising offset for data parsing
    
    ir_header = Header.fromData(ir_data, offset)
    #print "Received Header from root server  ", ir_header
    offset += HEADER_SIZE

    #print " Answer Count ", ir_header._ancount, " NS count ", ir_header._nscount, " Additional Records count ", ir_header._arcount
            
    if ir_header._ancount > 0: # if we got an answer break this loop
        answer_available = True
        if resolving_top_domain == False: # This is the  final answer. 
            #print "We got an Answer!!!!!!!! wohoooo "
            shouldContinue = False;    
    
    total_number_of_records = ir_header._ancount + ir_header._nscount + ir_header._arcount
    #print "Total Records in response ",  total_number_of_records
  
    myQE = QE.fromData(ir_data, offset) 
    
    query_size = len(myQE); # FIXME: Assuming one query

    offset += query_size
    #print "Query in Response ", myQE

    rr_count = 0 # Variable to iterate through Resource records
    domain_zone = OrderedDict()
    iAddressEntry = dict() 
    
    # We clear both local caches before iterating through the records.
    nscache_local.clear() 
    acache_local.clear()

    # we iterate through all the records and load to local cache. Note we consider only TYPE_A, _NS and _CNAME records 
    while rr_count < total_number_of_records:
        resource_record, record_length = RR.fromData(ir_data, offset)
        
        #print "Total", total_number_of_records, "rr_count ", rr_count, "Length  ", record_length,  resource_record
        
        if resource_record._type == RR.TYPE_NS:
            domain_zone[resource_record._nsdn] = CacheEntry(expiration=resource_record._ttl, authoritative=True)
            nscache_local[resource_record._dn] = domain_zone   
            domain = resource_record._dn
            
        elif resource_record._type == RR.TYPE_A:
            acache_local[(resource_record._dn)] = ACacheEntry(dict([(InetAddr(inet_ntoa(resource_record._addr)), CacheEntry(expiration=resource_record._ttl, authoritative=True))]))
            if answer_available == True and rr_count == 0:
                #print "We got an Answer - ",  resource_record
                lastAnswer = resource_record   
                   
        elif answer_available and resource_record._type == RR.TYPE_CNAME: 
              
            if resource_record._type == RR.TYPE_CNAME:          
                iq_data = generate_query_packet_with_address(iq_data, resource_record._cname)
                #print resource_record._cname

                
            ns_to_query = ROOTNS_IN_ADDR
            cname_found = True
            
            shouldContinue = True # Answer is a CNAME, we will have to continue resolving
            
            if not resolving_top_domain:
                if address_resolution_stack.isEmpty():               
                    address_resolution_stack.push([myQE._dn, TYPE_CNAME])                       
            
                if resource_record._type == RR.TYPE_CNAME:          
                    cnamecache_current[resource_record._dn] = [resource_record._cname, resource_record._ttl] # Load the answer to CNAME cache.
                
            lastAnswer = resource_record 
            break;
        
        elif resource_record._type == RR.TYPE_SOA:
            soa_found = True
            shouldContinue = False # Answer is a SOA, we will break here
            break;
                               
        #print  rr_count, " -> ", resource_record     
        
        offset += record_length # Advance the read offset
        rr_count += 1 # Increment Resource record count       
        
    if not domain in nscache.keys() and domain in nscache_local.keys():
        nscache[domain] = nscache_local[domain]

    for key, value in acache_local.iteritems():
        if not key in acache.keys():
            acache[key] = acache_local[key]    
            
    if answer_available == True and not cname_found: # We got an answer and its not a CNAME
        if resolving_top_domain == True: # This is a top level domain address, not the final answer
            query_dn = address_resolution_stack.pop()
            if query_dn[1] == TYPE_DN:
                iq_data = generate_query_packet_with_address(iq_data, str(query_dn[0])) # Generate a query packet with actual address to resolve
                ns_to_query = str(inet_ntoa(lastAnswer._addr)) # We will try resolving the address from the TLD
                resolving_top_domain = False # Un-set this flag, as we have resolved TLD     
                #print "We got an answer for a TLD ", lastAnswer, ns_to_query 
                #sleep(2)
            else:
                print "query_dn[1] != TYPE_DN: from Stack, something wrong !!!"
                #sleep(100)
    
    elif len(acache_local) != 0 and not cname_found and not soa_found: # Normal recursive iteration, if we have Glue records
        ns_cache_length = len(nscache_local[domain])        
        #print ns_cache_length, len(nscache_local), len(nscache)
        for i in range(0, ns_cache_length): #  Iterate through all the glue records
            #print nscache_local
            #print "Domain ", domain, i, ns_cache_length
            isSuccess, ns_to_query = find_next_iAddr_from_domain(domain, i) # Find an Internet Address for current Domain.
            if (isSuccess == True): # If we got an NS IP to resolve, break  
                break;             
        #print "Normal Sequence", ns_to_query
        if not ns_to_query:
            print  "Error ns_to_query=NULL -- We shouldn't reach here !!"
            
    elif len(acache_local) == 0 and not cname_found and not soa_found: # There are No glue records, We will have to resolve a TL NS address  
        isSuccess = False;
        ns_to_query = 0;
        
        if domain in nscache.keys():
            ns_cache_length = len(nscache[domain])                
            # Check if the IP address is already available in A-cache from any previous query
            for i in range(0, ns_cache_length): #  
                isSuccess, ns_to_query = find_next_iAddr_from_domain(domain, i) # Find an Internet Address for current Domain.
                if (isSuccess == True): # If we got an NS IP to resolve, break
                    break;                      
        if (isSuccess == False) and ns_to_query==0:                                
            domain_to_resolve = nscache_local[domain].keys()
            iq_data = generate_query_packet_with_address(iq_data, str(domain_to_resolve[0])) # Create a query packet with NS 
            ns_to_query = ROOTNS_IN_ADDR # Not available in cache, let start querying from Root server            
        resolving_top_domain = True # We are resolving a TLD
        #actual_query_address = myQE._dn # Lets store the until we have resolved the TLD
        address_resolution_stack.push([myQE._dn, TYPE_DN])
        #sleep(10)                               
  
  
  if address_available_in_cname_cache == True:
    print "Address available in Cache!"
    #print "Domain",   requestQuery._dn
    #print cnamecache
    rr_data = append_cname_aliases_from_cache(rr_data, requestQuery._dn)
        
      
  if address_resolution_stack.size() > 1:
    print "address_resolution_stack has more than one element, We haven't resolved everything. This is Wrong !!!!!!!"   
     
  elif not address_resolution_stack.isEmpty() and not soa_found:
    query_dn = address_resolution_stack.pop()
    if query_dn[1] != TYPE_CNAME:
     print "query_dn[1] != TYPE_CNAME"
     rr_data = generate_response_with_dn(rq_data, requestQuery._dn, True) # We have to generate a response with actual query address not the CNAME
    else:
        #print "Actual query address - ", query_dn[0]
        rr_data = generate_response_with_dn(ir_data, query_dn[0], False) # We have to generate a response with actual query address not the CNAME.
        # Append the entire CNAME tree answer section from the CNAME cache.
        rr_data = append_cname_aliases_from_current_cache(rr_data, query_dn[0])    
        
  #If we have resolved the query from cache.
  elif soa_found == True and not address_resolution_stack.isEmpty():
    query_dn = address_resolution_stack.pop()
    rr_data = generate_response_with_dn(ir_data, query_dn[0], False) # We have to generate a response with actual query address not the CNAME.   
  
  elif address_available_in_cache == False and address_available_in_cname_cache == False:
    rr_data = ir_data # Normal sequence, We will return the response received from Root servers           

  if socket_timedout:
    rr_data = generate_response_with_dn(rq_data, requestQuery._dn, True) # We have to generate a response with actual query address not the CNAME.
  else:
    rr_data = append_athoritive_glue_records_from_cache(rr_data);
  
  print "Responding to Client >>> "
  ss.sendto(rr_data, address)


      
