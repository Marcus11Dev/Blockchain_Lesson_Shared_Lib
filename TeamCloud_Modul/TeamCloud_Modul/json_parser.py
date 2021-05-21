import json
from collections import namedtuple

from .Blockchain import Block, Blockchain, Transaction
#from Functionality.Blockchain.Node import Node

Message = namedtuple('Message', ['sender','receiver', 'parser_type', 'message_type', 'payload', 'checksum'])

from hashlib import md5
def get_checksum(payload):
    return md5(str(payload).encode()).hexdigest()

class JSON_Parser:
    # Init Class
    #def __init__(self):
    #    self.test = 1

    #========================== Public ==========================
    def parse_message_to_dump(self, msg):
        self.sender = msg.sender
        self.receiver = msg.receiver
        self.parser_type = msg.parser_type
        self.message_type = msg.message_type
        self.payload = msg.payload
        self.checksum = msg.checksum

        dump = json.dumps({"sender": self.__parse_sender_to_dump(),
                            "receiver": self.__parse_receiver_to_dump(),
                            "parser_type": self.__parse_parser_type_to_dump(),
                            "message_type": self.__parse_message_type_to_dump(),
                            "payload": self.__parse_payload_to_dump(),
                            "checksum": self.__parse_checksum_to_dump()})

        return dump

    def parse_dump_to_message(self, dump):
        self.sender = self.__parse_dump_to_sender(dump["sender"])
        self.receiver = self.__parse_dump_to_receiver(dump["receiver"])
        self.parser_type = self.__parse_dump_to_parser_type(dump["parser_type"])
        self.message_type = self.__parse_dump_to_message_type(dump["message_type"])
        self.payload = self.__parse_dump_to_payload(dump["payload"])
        self.checksum = self.__parse_dump_to_checksum(dump["checksum"])
        
        msg = Message(sender=self.sender,
                    receiver=self.receiver,
                    parser_type=self.parser_type,
                    message_type = self.message_type,
                    payload=self.payload,
                    checksum=self.checksum)

        return msg

    #========================== Private ==========================
    ## Sender
    def __parse_dump_to_sender(self, dump):
        return dump

    def __parse_sender_to_dump(self):
        return self.sender

    ## Receiver
    def __parse_dump_to_receiver(self, dump):
        return dump

    def __parse_receiver_to_dump(self):
        return self.receiver

    ## Parser type
    def __parse_dump_to_parser_type(self, dump):
        return dump

    def __parse_parser_type_to_dump(self):
        return self.parser_type

    ## Message type
    def __parse_dump_to_message_type(self, dump):
        return dump

    def __parse_message_type_to_dump(self):
        return self.message_type

    ## Payload
    def __parse_dump_to_payload(self, dump):
        if self.parser_type=='type_block':
            payload = self.parse_dump_to_block(dump)
        elif self.parser_type=='type_chain':
            payload = self.parse_dump_to_chain(dump)
        elif self.parser_type=='...':
            payload = 'ToDo'
        elif self.parser_type=='type_default':
            payload = dump           
        else:
            print("Incoming message has unknown message Type!") # Undefined Message Type received

        return payload
    
    def __parse_payload_to_dump(self):
        if self.parser_type=='type_block':
            dump = self.parse_block_to_dump(self.payload)
        elif self.parser_type=='type_chain':
            dump = self.parse_chain_to_dump(self.payload)
        elif self.parser_type=='...':
            dump = 'ToDo'
        elif self.parser_type=='type_default':
            dump = self.payload           
        else:
            print("Incoming message has unknown message Type!") # Undefined Message Type received

        return dump

    ## Checksum
    def __parse_dump_to_checksum(self, dump):
        return dump

    def __parse_checksum_to_dump(self):
        return self.checksum

    ### Specific Parser
    ## Block
    def parse_dump_to_block(self, dump):

        transaction_obj = Transaction(dump["transactions"][0], 
                                        dump["transactions"][1],
                                        dump["transactions"][2],
                                        dump["transactions"][3],
                                        dump["transactions"][4],
                                        dump["transactions"][5])    


        block = Block(dump["index"],
                    transaction_obj,
                    dump["timestamp"],
                    dump["previous_hash"],
                    dump["nonce"],
                    dump["hash"])

        return block
    
    def parse_block_to_dump(self, block):
        return block.__dict__

    ## Chain
    def parse_dump_to_chain(self, dump):
        generated_blockchain = Blockchain()
        for block_data in dump:
            block = self.parse_dump_to_block(block_data)
            generated_blockchain.chain.append(block)

        return generated_blockchain.chain

    def parse_chain_to_dump(self, chain):
        chain_data = []
        for block in chain:
            chain_data.append(block.__dict__)
        return chain_data
    
    def parse_dump_to_keys_dict(self, dump):
        dump_json = json.loads(dump)
        keys_dict = {}
        for user in dump_json:
            keys_dict.update({user: dump_json[user].encode('utf-8')})

        return keys_dict

    def parse_keys_dict_to_dump(self, keys_dict):
        dump = {}
        for user in keys_dict:
            dump.update({user: keys_dict[user].decode('utf-8')})
            
        return json.dumps(dump)

    

