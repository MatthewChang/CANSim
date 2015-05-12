#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import random
import rsa  # 3rd party library: sudo pip install rsa
import math
import logging
from hash_encryption import *

bus = [None]
public_keys = {}
random.seed()

RSA_KEY_SIZE = 512
HMAC_KEY_SIZE = 512
CHANNEL_TAG_BYTE_SIZE = 2
CHANNEL_SETUP_SIGN_BYTE_SIZE = 4
MAX_MESSAGE_ID_BYTE_SIZE = 11
HASH_FN = 'sha256'

debug = True

logging.basicConfig(filename='example.log', filemode='w', level=logging.INFO)

class CAN_Message:

    def __init__(self,id,source,tag,data,time,other=None):
        self.id = id
        self.tag = tag #MUST BE STRING
        self.data = data #MUST BE STRING
        self.ack_bit = 0
        self.source = source #INTEGER from 0-256
        self.creation_time = time  # not part of the message, used for analysis
        self.other = other  # any other analysis meta-data we want to store
        assert self.valid_message(), 'Invalid Message sizes'

    def valid_message(self):
        if self.id.bit_length() > MAX_MESSAGE_ID_BYTE_SIZE: return False
        if self.ack_bit.bit_length() > 1: return False
        if self.source == -1:
            if len(self.data) > CHANNEL_SETUP_SIGN_BYTE_SIZE or len(self.tag) > (8-CHANNEL_SETUP_SIGN_BYTE_SIZE): return False
            return True
        elif self.source >=0 and self.source < 265:
            if len(self.tag) > CHANNEL_TAG_BYTE_SIZE or len(self.data) > (8-CHANNEL_TAG_BYTE_SIZE): return False
            return True
        else: return False

    def get_ack(self):
        return self.ack_bit == 1

    def ack(self):
        self.ack_bit = 1

    def __str__(self):
        if self.other is None:
            return  ' ID: ' +str(self.id)+' SOURCE: '+str(self.source)+' DATA: ' +str(self.data)+ ' ACK: ' +str(self.ack_bit)+ ' OTHER: None'
        else:
            return  ' ID: ' +str(self.id)+ ' SOURCE: '+str(self.source)+' DATA: ' +str(self.data)+ ' ACK: ' +str(self.ack_bit)+ ' OTHER: ' +self.other


class CAN_Node:

    def __init__(self,node_id,bp,public_keys):

        assert node_id < 2048

        self.message_queue = []
        self.channel_keys = {} #source ID:(hmac_key, most recent_tag)
        self.channel_setup = {} #source ID:(growing signature, growing hmac key)
        self.message_queue = []
        self.messages_sent = 0
        self.total_latency = 0
        self.node_id = node_id
        self.broadcast_properties = bp
        self.hash_chain = None

        (pub_key, priv_key) = rsa.newkeys(RSA_KEY_SIZE)
        public_keys[node_id] = pub_key
        self.private_key = priv_key

    def try_write_to_bus(self, message, bus):
        if bus[0] == None or message.id < bus[0].id:
            bus[0] = message
            logging.info('\t' + str(self.node_id) + ' wrote to BUS: ' +  str(message))
            return True
        return False

    def has_message(self):
        return len(self.message_queue) > 0

    def process(self, bus, tick_number):
        r = random.uniform(0, 1)
        for (b, p) in self.broadcast_properties.items():
            if r < p:
                self.message_queue.append(CAN_Message(b, self.node_id, "1", "1", tick_number))

        if bus[0] != None:  # If there is a message on the bus
            if self.has_message() and bus[0].id == self.message_queue[0].id and bus[0].get_ack():
                # Our message acked and made it back to us means all other nodes
                # have seen it
                m = bus[0]
                bus[0] = None
                logging.info('\t' + str(self.node_id) + ' taking its acked message off the bus: ' + str(m.id))
                self.message_queue = self.message_queue[1:]
                self.messages_sent += 1
                latency = tick_number - m.creation_time
                self.total_latency += latency

            else:
                # if we've made it to here there was a message in the bus
                # which was not our own so we ack
                bus[0].ack()
                self.process_message(bus[0])

        if self.has_message():  # If we have a message to write
            if self.try_write_to_bus(self.message_queue[0], bus):  # Try to write it
                return   # Return if wrote message

    def setup_write_channel(self, num_messages, tick_number=0):

        channel_key = gen_str_key(HMAC_KEY_SIZE)
        seed = gen_str_key(HMAC_KEY_SIZE)
        signature = rsa.sign(channel_key, self.private_key, 'SHA-1')
        self.hash_chain = HashChain(seed, num_messages, CHANNEL_TAG_BYTE_SIZE,
                                    channel_key, HASH_FN)
        init_value = self.hash_chain.get_init_value()

        print channel_key, len(channel_key)
        print signature, len(signature)

        # breaks down key, signature into separate messages to send
        # only work if using SHA-256 and HMAC_KEY_SIZE = 256
        for i in xrange(int(math.ceil(HMAC_KEY_SIZE / 4))):
            tag = signature[i * 4:(i + 1) * 4]
            data = channel_key[i * 4:(i + 1) * 4]
            self.message_queue.append(CAN_Message(self.node_id,-1,tag,data,tick_number,other='[channel setup message]'))
            logging.info('\t' + str(self.node_id) + ' wrote channel setup message to BUS')

        # Announce creation of hashchain on the network

        logging.info('\t' + str(self.node_id) + ' setting up write channel with key ' + channel_key)

    def process_message(self, m):
        if m.id < 2048:
            #checks if this message is a channel setup message (MSB is 0)
            # message ID is 11 bits, MSB is 0 iff number is < 2048
            source_id = m.id
            if source_id in self.channel_setup:
                self.channel_setup[source_id][0] += m.tag
                self.channel_setup[source_id][1] += m.data
            else:
                self.channel_setup[source_id] = [m.tag, m.data]

            if len(self.channel_setup[source_id][1]) == HMAC_KEY_SIZE:
                #we recieved all the necessary data to verify
                if rsa.verify(self.channel_setup[source_id][1], self.channel_setup[source_id][0], public_keys[source_id]):
                    self.channel_data[source_id] = (self.channel_data[source_id][1], None)
                    print self.node_id,': NEW CHANNEL VERIFIED'
                else:
                    print self.node_id,': CHANNEL SPOOF DETECTED'

        else:
            # DATA MESSAGE FORMAT [id = 1..., tag = 2 bytes, data
            logging.info('\t' + str(self.node_id) + ' read a data tranmission message')

    def __str__(self):
        return ''

#security issues:
#   hijacking first initial value channel message

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

node0 = CAN_Node(0, {2: 0.2}, public_keys)
node1 = CAN_Node(1, {8: 0.1}, public_keys)
node2 = CAN_Node(2, {4: 0.3}, public_keys)
node0.setup_write_channel(10)
nodes = [node0, node1, node2]

simticks = 100
for i in xrange(simticks):
    logging.warning('NOW IN LEVEL ' + str(i))
    for n in nodes:
        logging.info('Start of BUS: ' + str(bus[0]))
        n.process(bus, i)

total_messages = 0
total_latency = 0
for (i, n) in enumerate(nodes):
    avg_latency = 0
    if n.messages_sent != 0:
        avg_latency = 1.0 * n.total_latency / n.messages_sent
    print 'Node:', i, 'messages:', n.messages_sent, 'avg latency:', avg_latency
    total_messages += n.messages_sent
    total_latency += n.total_latency

print 'Messages:', total_messages
print 'Average Latency:', 1.0 * total_latency / total_messages
print 'Public Keys:', public_keys



