import time
import random
from rsa_encryption import *
from hash_encryption import *

bus = [None]
random.seed()

class CAN_Message:
     def __init__(self,id,sig_bit,data,time):
          self.id = id
          self.sig_bit = sig_bit
          self.data = data
          self.ack_bit = 0
          self.tag = self.create_tag(data)
          self.creation_time = time #not part of the message, used for analysis
          assert self.valid_message(), "Invalid Message sizes";

     def valid_message(self):
          if(self.id.bit_length() <= 10 and
             self.sig_bit.bit_length() <= 1 and
             self.data.bit_length() <= 6*8 and
             self.tag.bit_length() <= 2*8 and
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
     def __init__(self,bp):
          self.message_queue = []
          self.private_key = None
          self.keys = []
          self.message_queue = []
          self.messages_sent = 0
          self.total_latency = 0;
          self.broadcast_properties = bp
          

     def try_write_to_bus(self,message,bus):
          if(bus[0] == None or message.id < bus[0].id):
               bus[0] = message
               return True
          return False

     def has_message(self):
          return len(self.message_queue) > 0

     def process(self,bus,tick_number):
          print "StartBUS:", bus[0]
          r = random.uniform(0,1)
          for b,p in self.broadcast_properties.items():
               if(r < p):
                    self.message_queue.append(CAN_Message(b,0,1,tick_number))
                                   
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

          
     def process_message(self,m):
          return
     
     def __str__(self):
          return ""
               
#assign each node ID
#setup public, private key for each node
#setup HMAC chain channels
#send traffic through channels
#refresh chain

nodes = []
nodes.append(CAN_Node({6: 0.2}))
nodes.append(CAN_Node({0: 0.1}))
nodes.append(CAN_Node({10: 0.3}))

simticks = 100
for i in xrange(simticks):
     for n in nodes:
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
