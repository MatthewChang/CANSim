#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import random
import rsa  # 3rd party library: sudo pip install rsa
import math
from collections import defaultdict
from hash_encryption import *

#TODO:
#   update LOG with actual ops, actual node names,
#   be able to turn on and off authentication

bus = [None]
public_keys = {}
random.seed()

LOG_FILE_NAME = 'cansim.log'
logfile = open(LOG_FILE_NAME,'w')

RSA_KEY_SIZE = 512
HMAC_KEY_SIZE = 512
CHANNEL_TAG_BYTE_SIZE = 2
CHANNEL_SETUP_SIGN_BYTE_SIZE = 4
MAX_MESSAGE_ID_BYTE_SIZE = 11
MAX_NODE_ID = 2**(MAX_MESSAGE_ID_BYTE_SIZE-1)
HASH_FN = 'sha256'

AUTHENTICATION_ON = False
COMPUTE_STATS = True

debug = True
log = True


class CAN_Message:

    def __init__(self,id,source,tag,data,time,auth=False):
        self.id = id
        self.tag = tag #MUST BE STRING
        self.data = data #MUST BE STRING
        self.ack_bit = 0
        self.source = source #INTEGER from 0-256
        self.creation_time = time  # not part of the message, used for analysis
        self.auth = auth  # any other analysis meta-data we want to store
        assert self.valid_message(), 'Invalid Message sizes'

    def valid_message(self):
        if self.id.bit_length() > MAX_MESSAGE_ID_BYTE_SIZE:
            print 'Invalid ID length', self.id
            return False
        if self.ack_bit.bit_length() > 1:
            print 'Invalid ACK bit length', self.ack_bit
            return False
        if self.source < 0 or self.source > 255:
            print 'Invalid source node ID', self.source
            return False
        if self.auth:
            if len(self.data) > CHANNEL_SETUP_SIGN_BYTE_SIZE or len(self.tag) > (8-CHANNEL_SETUP_SIGN_BYTE_SIZE):
                print 'Invalid data and signature size', self.tag, self.data
                return False
            return True
        else:
            if len(self.tag) > CHANNEL_TAG_BYTE_SIZE or len(self.data) > (8-CHANNEL_TAG_BYTE_SIZE):
                print 'Invalid data and tag size', self.tag, self.data
                return False
            return True

    def get_ack(self):
        return self.ack_bit == 1

    def ack(self):
        self.ack_bit = 1

    def __str__(self):
        return  '[id:'+str(self.id)+',source:'+str(self.source)+',tag:'+str(self.tag)+',data:' +str(self.data) + ']'


class CAN_Node:

    def __init__(self,node_id,broadcast_props,listen_to,is_malicious,public_keys):

        assert node_id < MAX_NODE_ID

        self.message_queue = []
        self.channel_keys = {} #source ID:[hmac_key, most recent_tag, most_recent_message]
        self.channel_setup = {} #source ID:[growing signature, growing hmac key]
        self.recieved_data = defaultdict(list) #source ID:[data1, data2,...],
        self.message_queue = []
        self.messages_sent = 0
        self.total_latency = 0
        self.node_id = node_id
        self.is_malicious = is_malicious
        self.broadcast_properties = broadcast_props
        self.listen_to = listen_to
        self.hash_chain = None

        (pub_key, priv_key) = rsa.newkeys(RSA_KEY_SIZE)
        public_keys[node_id] = pub_key
        self.private_key = priv_key


    def try_write_to_bus(self, message, bus, tick_number):
        if bus[0] == None or message.id < bus[0].id:
            bus[0] = message
            if message.tag == "1" and debug: print self.node_id, 'wrote unauthed/malicious message to bus'
            if message.auth:
                #if debug: print self.node_id, 'wrote channel setup message to BUS', message
                if log: logfile.write(str(tick_number) + " MESSAGE AUTH NODE" + str(self.node_id) + "\n")
            else:
                if debug: print self.node_id, 'wrote data or IV message to BUS', message
                if log: logfile.write(str(tick_number) + " MESSAGE DATA NODE" + str(self.node_id) + "\n")
            return True
        return False


    def has_message(self):
        return len(self.message_queue) > 0

    '''helper function to append to write queue
        set auth to True if want to send an authenticated message
        sets up hash_chain if necessary'''
    def append_write_queue(self, id, data, auth, tick_number):
        if not AUTHENTICATION_ON: assert not auth
        if auth:
            if self.hash_chain == None or self.hash_chain.is_stale:
                #need to create a new HashChain
                self.setup_write_channel(100, tick_number)
                assert self.hash_chain != None and not self.hash_chain.is_stale
                tag = self.hash_chain.get_next_tag(data)
                self.message_queue.append(CAN_Message(id, self.node_id, tag, data, tick_number, auth=False))

            else:
                tag = self.hash_chain.get_next_tag(data)
                self.message_queue.append(CAN_Message(id, self.node_id, tag, data, tick_number, auth=False))

        else:
            fake_tag = "1"
            self.message_queue.append(CAN_Message(id, self.node_id, fake_tag, data, tick_number, auth=False))


    def process(self, bus, tick_number):
        rand_float = random.uniform(0, 1)
        for (mID, prob) in self.broadcast_properties.items():
            if rand_float < prob: #with certain probability send message
                data = gen_str_key(6*8) #randomize data sent
                if AUTHENTICATION_ON and not self.is_malicious: 
                    self.append_write_queue(mID, data, True, tick_number)
                else: #random tag
                    self.append_write_queue(mID, data, False, tick_number)


        if bus[0] != None:  # If there is a message on the bus
            if self.has_message() and bus[0].id == self.message_queue[0].id and bus[0].get_ack():
                # Our message acked and made it back to us means all other nodes
                # have seen it
                m = bus[0]
                bus[0] = None
                self.message_queue = self.message_queue[1:]
                self.messages_sent += 1
                latency = tick_number - m.creation_time
                self.total_latency += latency

            else:
                # if we've made it to here there was a message in the bus
                # which was not our own so we ack
                bus[0].ack()
                self.process_message(bus[0], tick_number)

        if self.has_message():  # If we have a message to write
            if self.try_write_to_bus(self.message_queue[0], bus, tick_number):  # Try to write it
                return   # Return if wrote message


    def setup_write_channel(self, num_messages, tick_number=0):

        if debug: print self.node_id, 'setting up a new hash chain'

        channel_key = gen_str_key(HMAC_KEY_SIZE)
        seed = gen_str_key(HMAC_KEY_SIZE)
        signature = rsa.sign(channel_key, self.private_key, 'SHA-256')
        self.hash_chain = HashChain(seed, num_messages, CHANNEL_TAG_BYTE_SIZE,
                                    channel_key, HASH_FN)
        init_tag,init_message = self.hash_chain.get_init_tag()

        auth_message_queue = [] #store setup messages that we want to send
        
        # breaks down key, signature into separate messages to send
        # only work if using SHA-256 and HMAC_KEY_SIZE = 512
        for i in xrange(int(math.ceil(HMAC_KEY_SIZE / (8*4)))):
            tag = signature[i * 4:(i + 1) * 4]
            data = channel_key[i * 4:(i + 1) * 4]
            auth_message_queue.append(CAN_Message(self.node_id,self.node_id,tag,data,tick_number,auth=True))
            if log: logfile.write(str(tick_number) + " MESSAGE AUTH NODE" + str(self.node_id) + "\n")

        #send out initial value
        auth_message_queue.append(CAN_Message(1024+self.node_id,self.node_id,init_tag,init_message,tick_number,auth=False))

        self.message_queue = auth_message_queue + self.message_queue

    def process_message(self, m, tick_number):
        if m.id not in self.listen_to: return
        if m.id < MAX_NODE_ID:
            if AUTHENTICATION_ON:
                #if debug: print self.node_id,'recieved channel setup message from', m.source
                #checks if this message is a channel setup message (MSB is 0)
                # message ID is 11 bits, MSB is 0 iff number is < 1024
                source_id = m.id
                if source_id in self.channel_setup:
                    #hack to circumvent Python bus scheduling issue
                    #unsure why, but occasionally messages are sent out twice (ack/message queue issue?)
                    #probability of hack failure: 1/(256*256)
                    #discounts repeat messages
                    if m.data != self.channel_setup[source_id][1][-len(m.data):]:
                        self.channel_setup[source_id][0] += m.tag
                        self.channel_setup[source_id][1] += m.data
                    else:
                        if debug: print self.node_id, 'noticed repeat message from', source_id
                else:
                    self.channel_setup[source_id] = [m.tag, m.data]

                if len(self.channel_setup[source_id][1]) == HMAC_KEY_SIZE/8:
                    #we recieved all the necessary data to verify
                    try:
                        data = self.channel_setup[source_id][1]
                        signature = self.channel_setup[source_id][0]
                        rsa.verify(data, signature, public_keys[source_id])
                        self.channel_keys[source_id] = [self.channel_setup[source_id][1], None, None]
                        if debug: print self.node_id,'verified a channel from',source_id
                    except:
                        if debug: print self.node_id,'recieved a fake channel',source_id
            else:
                if debug: print self.node_id, 'found unauthed message data from', m.source
                self.recieved_data[m.source].append(m.data)
            
        else:
            # DATA MESSAGE FORMAT [id = 1..., tag = 2 bytes, data
            if m.source not in self.channel_keys:
                if debug: print self.node_id, 'found unauthed message data from', m.source
                if not AUTHENTICATION_ON: self.recieved_data[m.source].append(m.data)
                return
            else:
                if self.channel_keys[m.source][1] == None: #this must be the initial value message of the chain
                    self.channel_keys[m.source][1] = m.tag
                    self.channel_keys[m.source][2] = m.data
                    self.recieved_data[m.source] = [m.data]
                    if debug: print self.node_id, 'read a initial value message tranmission from', m.source
                else:
                    key = self.channel_keys[m.source][0]
                    prev_tag = self.channel_keys[m.source][1]
                    prev_message = self.channel_keys[m.source][2]
                    #another hack for same reason:
                    #for some reason, repeat messages seem to be going through on the bus
                    # because of some weird ack reason. checking explicitly for them, and dumping them
                    if not (m.tag == prev_tag and m.data == prev_message):
                        if HashChain.authenticate(prev_tag, prev_message, m.tag, m.data, key, HASH_FN, CHANNEL_TAG_BYTE_SIZE):
                            if debug: print self.node_id, 'verified message from %s sent over channel!' % m.source
                            self.recieved_data[m.source].append(m.data)
                            self.channel_keys[m.source] = [key, m.tag, m.data]
                        else:
                            if debug: print self.node_id, 'found spoof message data sent over channel from', m.source
                        

    def __str__(self):
        return ''

#security issues:
#   hijacking first initial value channel message
#   hijacking any channel setup message (DOS)

#logisitic issues
#malicious message DOS is really dependent on priority

# assign each node ID
# setup public, private key for each node
# setup HMAC chain channels
#   hmac key, initial value, length sent over (just to do hash)
#       this message is signed by RSA public key
#   reciever is able to verify that messages through channel come from sender
#   if you want: can encrypt messages in channel, based on recipients public key
#
#   using a keyed channel allows us to have more possible channels to use/replay prevention
#
#   more than one hash chain NOPE --> how much memory?
# send traffic through channels
# refresh chain

#You can choose to listen
node_id_map_str = {4: 'DASHBOARD', 1:'MOTOR_CONTROLLER', 0:'MOTOR', 3:'BRAKE', 2:'STEERING_WHEEL'}
print node_id_map_str

#WHAT CHANNELS THAT EACH THING BROADCASTS TO
mIDs = {
    'MOTOR_DATA':2000,
    'MOTOR_SETUP':0,
    'MOTOR_CONT_DATA':2001,
    'MOTOR_CONT_SETUP':1,
    'STEERING_DATA':2002,
    'STEERING_SETUP':2
}

DASHBOARD = CAN_Node(4, {}, [mIDs['MOTOR_CONT_DATA'], mIDs['MOTOR_CONT_SETUP']], False, public_keys)
MOTOR_CONTROLLER = CAN_Node(1, {mIDs['MOTOR_CONT_DATA']: 0.8}, [mIDs['MOTOR_DATA'], mIDs['MOTOR_SETUP'],mIDs['STEERING_DATA'],mIDs['STEERING_SETUP']], False, public_keys)
MOTOR = CAN_Node(0, {mIDs['MOTOR_DATA']: 0.2},[mIDs['MOTOR_CONT_DATA'],mIDs['MOTOR_CONT_SETUP']], False, public_keys)
BRAKE = CAN_Node(3, {}, [mIDs['MOTOR_CONT_DATA'],mIDs['MOTOR_CONT_SETUP']], False, public_keys)
STEERING_WHEEL = CAN_Node(2, {mIDs['STEERING_DATA']: 0.7}, [], True, public_keys)

node_id_map = {0: DASHBOARD, 1:MOTOR_CONTROLLER, 2:MOTOR, 3:BRAKE, 4:STEERING_WHEEL}
nodes = [DASHBOARD, MOTOR_CONTROLLER, MOTOR, BRAKE, STEERING_WHEEL]
#DASHBOARD.setup_write_channel(100)

def avg_latency(node,timestamp=0,should_log=False):
    avg_latency = 0
    if node.messages_sent != 0:
        avg_latency = 1.0 * node.total_latency / node.messages_sent
    if should_log: logfile.write(str(timestamp) + " AVGLATENCY NODE" + str(node.node_id) + " " + str(avg_latency) + "\n")
    return avg_latency

def total_messages(node,timestamp=0,should_log=False):
    if should_log: logfile.write(str(timestamp) + " TOTALM NODE" + str(node.node_id) + " " + str(node.messages_sent) + "\n")
    return node.messages_sent

def system_total_message(timestamp=0,should_log=False):
    total_messages = 0
    for n in nodes:
        total_messages += n.messages_sent
    if should_log: logfile.write(str(timestamp) + " STOTALM " + str(total_messages) + "\n")

def system_avg_latency(timestamp=0,should_log=False):
    total_messages = 0
    total_latency = 0
    for n in nodes:
        total_messages += n.messages_sent
        total_latency += n.total_latency
    if total_messages != 0:
        if should_log: logfile.write(str(timestamp) + " SAVGLATENCY " + str(1.0*total_latency/total_messages) + "\n")
    else:
        if should_log: logfile.write(str(timestamp) + " SAVGLATENCY " + str(0) + "\n")

simticks = 100
for i in xrange(simticks):
    system_avg_latency(i,log)
    system_total_message(i,log)
    for n in nodes:
        n.process(bus, i)
        if log: logfile.write(str(i) + " STATUS NODE" + str(n.node_id) + " " + str(len(n.message_queue)) + "\n")
        if bus[0] != None:
            if log: logfile.write(str(i) + " BUS_HEAD NODE" + str(bus[0].source) + " " + str(bus[0].id) + " " + str(bus[0].tag) + " " + str(bus[0].data) + "\n")
        else:
            if log: logfile.write(str(i) + ' BUS_HEAD NONE\n')
        avg_latency(n, i,log)
        total_messages(n, i,log)

print '...'
print 'Number of Simulation Rounds: 100'
for n in nodes:
    print 'Node:', node_id_map_str[n.node_id]
    print '\t','Length of Message Queu:', len(n.message_queue)
    print '\t','Total Message Sent:', n.messages_sent
    print '\t','Average Message Latency:', avg_latency(n)

print 'System Average Latency:', system_avg_latency()
print 'System Total Messages Sent:', system_total_message()
print 
print 'Public Keys:', public_keys

logfile.close()
