
from network_simulator import NetworkSimulator, Packet, EventEntity
from enum import Enum
from struct import pack, unpack

class GBNHost():

    # The __init__ method accepts:
    # - a reference to the simulator object
    # - the value for this entity (EntityType.A or EntityType.B)
    # - the interval for this entity's timer
    # - the size of the window used for the Go-Back-N algorithm
    def __init__(self, simulator, entity, timer_interval, window_size):
        
        # These are important state values that you will need to use in your code
        self.simulator = simulator
        self.entity = entity
        
        # Sender properties
        self.timer_interval = timer_interval        # The duration the timer lasts before triggering
        self.window_size = window_size              # The size of the seq/ack window
        self.window_base = 0                        # The last ACKed packet. This starts at 0 because no packets 
                                                    # have been ACKed
        self.next_seq_num = 0                       # The SEQ number that will be used next

        
        self.unACKed_buffer = []
        self.app_layer_buffer = []

        self.expected_seq_val = 0
        self.last_ACK = self.make_pkt(0, -1, 0, "")
   

    # @param self: reference to gbn_host
    # @param packet_type: 0 for ACK or 128 for Data
    # @param packet_number: seq # or ACK #
    # @param checksum: checksum from payload
    # @param payload: string message to be packed
    def make_pkt(self, packet_type, packet_number, checksum, payload):
        packet_length = len(payload)
        packet_byte_array = pack("!HiHI"+str(packet_length)+"s", 
            packet_type, packet_number, 0, packet_length, payload.encode('utf-8'))

        checksum = self.get_checksum(packet_byte_array)

        return pack("!HiHI"+str(packet_length)+"s", 
            packet_type, packet_number, checksum, packet_length, payload.encode('utf-8'))
        

    def extract_payload(self, payload):
        try:
            packet_type = unpack('!H', payload[:2])[0]
            packet_number = unpack('!i', payload[2:6])[0]
            checksum = unpack('!H', payload[6:8])[0]
            payload_length = unpack("!I", payload[8:12])[0]
            message = unpack('!'+str(payload_length)+'s', payload[12:])[0]
        except:
            return [0, 0, 0, 0, ""]
        return [packet_type, packet_number, checksum, payload_length, message.decode()]

    def get_checksum(self, packet):
        if len(packet) % 2 == 1:
            packet = packet + bytes(1)
        
        summed_words = 0
        for i in range(0, len(packet), 2):#16 bit words
            word = packet[i] << 8 | packet[i+1] 
            summed_words += word
        result = (summed_words & 0xffff) + (summed_words >> 16)

        checksum = ~result & 0xffff
        return checksum

    ###########################################################################################################
    ## Core Interface functions that are called by Simulator

    # This function implements the SENDING functionality. It should implement retransmit-on-timeout. 
    # Refer to the GBN sender flowchart for details about how this function should be implemented
    def receive_from_application_layer(self, payload):
        #print("NSN: ", self.next_seq_num)
        if self.next_seq_num < (self.window_base + self.window_size):
            self.unACKed_buffer.append(self.make_pkt(128, self.next_seq_num, 0, payload))
            self.simulator.pass_to_network_layer(self.entity, self.unACKed_buffer[self.next_seq_num], False)
            if self.window_base == self.next_seq_num:
                self.simulator.start_timer(self.entity, self.timer_interval)
            self.next_seq_num += 1
        else:
            self.app_layer_buffer.append(payload)

        

    # This function implements the RECEIVING functionality. This function will be more complex that
    # receive_from_application_layer(), it includes functionality from both the GBN Sender and GBN receiver
    # FSM's (both of these have events that trigger on receive_from_network_layer). You will need to handle 
    # data differently depending on if it is a packet containing data, or if it is an ACK.
    # Refer to the GBN receiver flowchart for details about how to implement responding to data pkts, and
    # refer to the GBN sender flowchart for details about how to implement responidng to ACKs
    def receive_from_network_layer(self, byte_data):
        data = self.extract_payload(byte_data)
        #rint(data)
        corrupt = self.is_corrupt(byte_data)
        payload = data[4]
        if data[0] == 0 and not corrupt: 
            ack_num = data[1] 
            if ack_num >= self.window_base:
                self.window_base = ack_num + 1
                self.simulator.stop_timer(self.entity)
                if self.window_base != self.next_seq_num:
                   self.simulator.start_timer(self.entity, self.timer_interval)
                while (len(self.app_layer_buffer) > 0) and (self.next_seq_num < (self.window_base + self.window_size)):
                    payload = self.app_layer_buffer.pop()
                    #print("Pre-Unacked, ", self.next_seq_num)
                    #Make an ACK corresponding to the same NSN
                    self.unACKed_buffer.append(self.make_pkt(128, self.next_seq_num, 0, payload))
                    #print("Post-Unacked")
                    self.simulator.pass_to_network_layer(self.entity, self.unACKed_buffer[self.next_seq_num], False)
                    if self.window_base == self.next_seq_num:
                        self.simulator.start_timer(self.entity, self.timer_interval)
                    self.next_seq_num += 1
        elif data[0] == 0 and corrupt: 
            self.simulator.pass_to_network_layer(self.entity, self.last_ACK, True)
        else: #Receiver
            corrupt = self.is_corrupt(byte_data)
            if not corrupt and data[1] == self.expected_seq_val and data[3] != 0:
                #print("ok")
                self.simulator.pass_to_application_layer(self.entity, data[4])
                self.last_ACK = self.make_pkt(0, self.expected_seq_val, 0, "") #ACK
                self.simulator.pass_to_network_layer(self.entity, self.last_ACK, True) #ACK
                self.expected_seq_val += 1
            else:
                #print("!ok")
                self.simulator.pass_to_network_layer(self.entity, self.last_ACK, True)
            #self.last_ACK = self.make_pkt(0, -1, 0, "")



    # This function is called by the simulator when a timer interrupt is triggered due to an ACK not being 
    # received in the expected time frame. All unACKed data should be resent, and the timer restarted
    def timer_interrupt(self):
        self.simulator.start_timer(self.entity, self.timer_interval)
        for i in range(self.window_base, self.next_seq_num):
            self.simulator.pass_to_network_layer(self.entity, self.unACKed_buffer[i], False)


    # This function should check to determine if a given packet is corrupt. The packet parameter accepted
    # by this function should contain a byte array
    def is_corrupt(self, packet):
        if len(packet) % 2 == 1:
            packet = packet + bytes(1)

        summed_words = 0
        for i in range(0, len(packet), 2):#16 bit words
            word = packet[i] << 8 | packet[i+1] 
            summed_words += word
        corrupt = (summed_words & 0xffff) + (summed_words >> 16)
        #print("corrupt? ", corrupt)

        if corrupt == 65535:
            return False
        else:
            return True
