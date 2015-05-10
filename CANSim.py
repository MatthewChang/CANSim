import time
from rsa_encryption import *

bus = [None]

class CAN_Message:
     def __init__(self,id,sig_bit,data):
          self.id = id
          self.sig_bit = sig_bit
          self.data = data
          self.ack_bit = 0
          assert self.valid_message(), "Invalid Message sizes";

     def valid_message(self):
          if(self.id.bit_length() <= 10 and
             self.sig_bit.bit_length() <= 1 and
             self.data.bit_length() <= 64 and
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

def genSignature(message,e,n):
     data = message.data
     sig = pow(data,e,n)
     return CAN_Message(message.id,1,sig)
     
class CAN_Node():
     def __init__(self):
          self.message_queue = []
          self.out_ids = []
          self.in_map = {}
          self.private_key = None
          self.keys = []
          self.message_queue = []
          self.messages_sent = 0
          
     def setup(self):
          for o in self.out_ids:
               self.message_queue.append(CAN_Message(o,0,1))

     def try_write_to_bus(self,message,bus):
          if(bus[0] == None or message.id < bus[0].id):
               bus[0] = message
               return True
          return False

     def has_message(self):
          return len(self.message_queue) > 0

     def process(self,bus):
          print "StartBUS:",bus[0]
          if(self.has_message()): #If we have a message to write
               if(self.try_write_to_bus(self.message_queue[0],bus)): #Try to write it
                    return #Return if wrote message

          if(bus[0] != None): #If there is a message on the bus
               if(self.has_message() and
                  bus[0].id == self.message_queue[0].id and
                  bus[0].get_ack()):
                    #Our message acked and made it back to us means all other nodes
                    #have seen it
                    print "S: "+str(bus[0].id)
                    self.message_queue = self.message_queue[1:]
                    bus[0] = None
                    self.messages_sent += 1
                    return #Clear the bus for fairness
                    
               #if we've made it to here there was a message in the bus
               #which was not our own so we ack
               bus[0].ack()
               i = bus[0].id
               d = bus[0].data
               if(i in self.in_map):
                    print "Queue", i
                    outid = self.in_map[i]
                    for m in self.message_queue:
                         if(m.id == outid):
                              return #This prevents bad ack timing creating an infinite message queue
                    self.message_queue.append(CAN_Message(outid,0,d+1))

     def __str__(self):
          return "OUT_IDS: "+str(self.out_ids)+"IN_IDS: "+str(self.in_map)
               
connectivity = {0:[1,2,3,4,5],
              1:[0],
               2:[1],
                3:[1],
                4:[1],
                5:[1]}
connectivity_matrix = [ [0]*len(connectivity) for x in connectivity ]
connection_index = 1
for i,c in connectivity.items():
     for j in c:
          connectivity_matrix[i][j] = connection_index
          connection_index += 1
print connectivity_matrix

nodes = [CAN_Node() for x in connectivity]

connections = 0
for i in range(0,len(nodes)):
     for j in range(0,len(nodes)):
          val = connectivity_matrix[i][j]
          if(val != 0):
               nodes[i].out_ids.append(val)
               nodes[j].in_map[val]=connectivity_matrix[j][i]
          
for o in nodes:
     o.setup()
     print o

simticks = 100
for i in xrange(simticks):
     for n in nodes:
          n.process(bus)

total_messages = 0
for i,n in enumerate(nodes):
     print "Node",i," messages ",n.messages_sent
     total_messages += n.messages_sent

print "Messages:", total_messages
print "Average Latency:", 1.0*total_messages/simticks
'''nodes.append(MotorController_Node())
nodes.append(Motor_Node())
simticks = 100
for i in xrange(simticks):
     for n in nodes:
          n.process(bus);'''
