import time
import random
import rsa #3rd party library: sudo pip install rsa
from hash_encryption import *

bus = [None]
public_keys = {}
random.seed()

RSA_KEY_SIZE = 512
HMAC_KEY_SIZE = 128
TAG_BYTE_SIZE = 2
MAX_MESSAGE_ID_BYTE_SIZE = 11
HASH_FN = 'sha256'

class CAN_Message:
     def __init__(self,id,sig_bit,tag,data,time):
          self.id = id
          self.sig_bit = sig_bit
          self.tag = tag
          self.data = data
          self.ack_bit = 0
          self.creation_time = time #not part of the message, used for analysis
          assert self.valid_message(), "Invalid Message sizes";

     def valid_message(self):
          if(self.id.bit_length() <= MAX_MESSAGE_ID_BYTE_SIZE and
             self.sig_bit.bit_length() <= 1 and
             self.data.bit_length() <= 6*8 and
             self.tag.bit_length() <= TAG_BYTE_SIZE*8 and
             self.ack_bit.bit_length() <= 1):
               return True
          else:
               return False

     def get_ack(self):
          return self.ack_bit == 1;

     def ack(self):
          self.ack_bit = 1
          
     def __str__(self):
          return "ID: "+str(self.id)+" SIG_BIT: "+str(self.sig_bit)+" DATA: "+str(self.data)+" ACK: "+str(self.ack_bit)

class CAN_Node():
     def __init__(self, node_id, bp, public_keys):
          self.message_queue = []
          self.hmac_keys = {}
          self.message_queue = []
          self.messages_sent = 0
          self.total_latency = 0
          self.node_id = node_id
          self.broadcast_properties = bp
          self.hash_chain = None
          
          (pub_key, priv_key) = rsa.newkeys(RSA_KEY_SIZE)
          public_keys[node_id] = pub_key
          self.private_key = priv_key


     def try_write_to_bus(self,message,bus):
          if(bus[0] == None or message.id < bus[0].id):
               bus[0] = message
               print '\t', self.node_id, 'wrote to BUS:', message
               return True
          return False

     def has_message(self):
          return len(self.message_queue) > 0

     def process(self,bus,tick_number):
          r = random.uniform(0,1)
          for b,p in self.broadcast_properties.items():
               if(r < p):
                    self.message_queue.append(CAN_Message(b,0,1,1,tick_number))
                                   
          if(bus[0] != None): #If there is a message on the bus
               if(self.has_message() and
                  bus[0].id == self.message_queue[0].id and
                  bus[0].get_ack()):
                    #Our message acked and made it back to us means all other nodes
                    #have seen it
                    m = bus[0]
                    bus[0] = None
                    print "S: "+str(m.id)
                    self.message_queue = self.message_queue[1:]
                    self.messages_sent += 1
                    latency = tick_number - m.creation_time
                    self.total_latency += latency
               else:                         
                    #if we've made it to here there was a message in the bus
                    #which was not our own so we ack
                    bus[0].ack()
                    self.process_message(bus[0])

          if(self.has_message()): #If we have a message to write
               if(self.try_write_to_bus(self.message_queue[0],bus)): #Try to write it
                    return #Return if wrote message

     def setup_write_channel(self,num_messages,tick_number=0):

          channel_key = gen_str_key(HMAC_KEY_SIZE)
          seed = gen_str_key(HMAC_KEY_SIZE)
          self.hash_chain = HashChain(seed, num_messages, TAG_BYTE_SIZE, channel_key, HASH_FN)
          #self.message_queue.append(CAN_Message(b,0,1,1,tick_number))

          #Announce creation of hashchain on the network
          print '\t', self.node_id, 'setting up write channel with key', channel_key

     '''
        0b0 prefix in messages: Channel Setup Signature/Channel Listen Key Message
            Rest of prefix: [source node ID - 9 bits at most]
            Payload: [4 bytes sign] [4 bytes key]
        0b1 prefix in messages: data message over channel
     '''
     def process_message(self,m):
          if m.id  < 2048: #message ID is 11 bits, MSB is 0 iff number is < 2048
               print '\t',self.node_id, 'read a channel setup message'
          else:
               print '\t',self.node_id, 'read a data tranmission message'

     
     def __str__(self):
          return ""

#assign each node ID
#setup public, private key for each node
#setup HMAC chain channels
#   hmac key, initial value, length sent over (just to do hash)
#       this message is signed by RSA public key
#   reciever is able to verify that messages through channel come from sender
#   if you want: can encrypt messages in channel, based on recipients public key
#   
#   using a keyed channel allows us to have more possible channels to use/replay prevention
#
#   more than one hash chain NOPE --> how much memory?
#send traffic through channels
#refresh chain

nodes = []
nodes.append(CAN_Node(0, {2: 0.2}, public_keys))
nodes.append(CAN_Node(1, {8: 0.1}, public_keys))
nodes.append(CAN_Node(2, {4: 0.3}, public_keys))

simticks = 100
for i in xrange(simticks):
     for n in nodes:
          print "Start of BUS:", bus[0]
          n.process(bus,i)

total_messages = 0
total_latency = 0
for i,n in enumerate(nodes):
     avg_latency = 0
     if(n.messages_sent != 0):
          avg_latency = 1.0*n.total_latency/n.messages_sent
     print "Node:",i,"messages:",n.messages_sent,"avg latency:",avg_latency
     total_messages += n.messages_sent
     total_latency += n.total_latency

print "Messages:", total_messages
print "Average Latency:", 1.0*total_latency/total_messages

'''nodes.append(MotorController_Node())
nodes.append(Motor_Node())
simticks = 100
for i in xrange(simticks):
     for n in nodes:
          n.process(bus);'''
