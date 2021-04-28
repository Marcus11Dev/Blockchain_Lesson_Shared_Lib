# -*- coding: utf-8 -*-
"""
Created on Sat Oct 24 10:56:51 2020

@author: Marcus
"""

from hashlib import sha256
from hashlib import md5
import numpy as np
import json
import os
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

#import Blockchain
from collections import namedtuple

from .Blockchain import Blockchain,Transaction, Block
from TeamCloud_Modul.json_parser import JSON_Parser

MAX_HEADERS_PER_MSG = 2000
Message = namedtuple('Message', ['sender','receiver', 'parser_type', 'message_type', 'payload', 'checksum'])

def get_checksum(payload):
    return md5(str(payload).encode()).hexdigest()

""" Creates an object which can be used to unpack blockchain specific Messages """    

class Message_():
    def __init__(self,sender,receiver,payload,message_type):
        self.sender = sender
        self.receiver = receiver
        self.payload = payload
        self.message_type = message_type
        self.checksum = md5(str(payload).encode()).hexdigest()
        self.headers = []

    def print_message(self):
        print("")
        print("Message Type = ", self.message_type)
        print("Sender = ", self.sender, ". Receiver = ", self.receiver)
        print("Payload = ", self.payload)
        print("")

class Node:
    def __init__(self,name, private_key = None, public_key = None):

        self.name = name
        self.__private_key = private_key
        self.__public_key = public_key
        self.user_public_key_map = {}
        self.filepath = os.path.dirname(os.path.abspath(__file__))
        self.backup_path = self.filepath + "/backup.txt"
        self.blockchain=Blockchain()
        self.json_parser = JSON_Parser()

        if name == "Cloud":
            if not self.read_backup():
                self.blockchain.create_genesis_block()
                self.init_coins()
  
        else:
            self.blockchain.create_genesis_block()
            
        self.balance = 0
        self.update_balance()         
        
        self.headers = [] # List containing the payload of headers messages (list of hashes)
    
    def init_coins(self):
        self.blockchain.add_new_transaction(Transaction('bank',self.name, 'InitCoin',1,100,0))
        self.blockchain.mine()
        self.write_backup()
    
    def update_balance(self):
        self.balance = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == self.name:
                self.balance-= block.transactions.amount
            
            elif block.transactions.receiver == self.name:
                self.balance+= block.transactions.amount

    def get_balance_of(self, name):
        balance = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == name:
                balance-= block.transactions.amount
            
            elif block.transactions.receiver == name:
                balance+= block.transactions.amount
        return balance
    
    def get_quotes_of(self, name, product):
        quantity = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == name and block.transactions.product == product:
                quantity+= block.transactions.quantity
            
            elif block.transactions.receiver == name and block.transactions.product == product:
                quantity-= block.transactions.quantity
        return quantity

    def check_transaction_validity(self, sender, receiver, product, quantity, amount_per_piece):
        if sender != "Cloud" and sender != "bank":
            # Check buyer has enough money
            if self.get_balance_of(sender) < quantity*amount_per_piece:
                return False

        if receiver != "Cloud":
            # Check seller has enough quantity
            if self.get_quotes_of(receiver, product) < quantity:
                return False

        return True
          
    def get_balance(self):
        self.update_balance()
        return self.balance
    
    def check_user_exists(self, name):
        exist = False
        for block in self.blockchain.chain:
            if block.transactions.receiver == name:
                exist = True
                break
            
        return exist

    def check_user(self, user, public_key):
        # 0:'User doesn´t exist',
        # 1:'User exists and has correct public key',
        # 2:'User exists and hasn´t correct public key',

        try:
            status = 0
            if user in self.user_public_key_map:
                status = 2
                if (self.user_public_key_map[user] == public_key):
                    status = 1

            return status

        except Exception as e:
            return 3
            
    def add_to_user_public_key_map(self, user, public_key):
        self.user_public_key_map.update( {user : public_key} )

    def get_user_public_key(self, user):
        try:
            return serialization.load_pem_public_key(self.user_public_key_map[user])
        except:
            return None
        
    def transaction(self, source, destination, product, quantity, amount, signature):
            self.blockchain.add_new_transaction(Transaction(source, destination, product, quantity, amount, signature))
            self.blockchain.mine()
            self.write_backup()

    def transaction_to(self,to,product, quantity,amount,signature):
        self.blockchain.add_new_transaction(Transaction(self.name,to,product, quantity, amount,signature))
        self.blockchain.mine()
        self.write_backup()
    
    def establish_connection(self):
        return
        
    def known_nodes(self):
        return
    
    def validate_chain(self,chain):
        status = True
        return status

    def create_dump_from_chain(self):
        chain_data = []
        for block in self.blockchain.chain:
            chain_data.append(block.__dict__)
        return json.dumps({"length": len(chain_data),
                            "chain": chain_data})
    
    def create_chain_from_dump(self, chain_dump):
        generated_blockchain = Blockchain()
        generated_blockchain.create_genesis_block()
        for idx, block_data in enumerate(chain_dump):
            if idx == 0:
                continue  # skip genesis block
            block = Block(block_data["index"],
                        block_data["transactions"],
                        block_data["timestamp"],
                        block_data["previous_hash"],
                        block_data["nonce"])
            proof = block_data['hash']
            added = generated_blockchain.add_block(block, proof)
            if not added:
                raise Exception("The chain dump is tampered!!")
        return generated_blockchain.chain

    def update_chain(self,chain):
        self.blockchain.chain = chain

    # Blockchain synchronisation part START

    def get_payload_for_get_headers_msg(self,start_hash = None, stop_hash = None):
        """
            Returns a list of two values, [start_hash,stop_hash].
        """
        if start_hash == None:
            start_hash = self.blockchain.last_block.hash
        if stop_hash == None:
            stop_hash = 0
        
        return start_hash, stop_hash

    def get_payload_for_headers_msg(self,start_hash,stop_hash):
        """
            Returns a list of hashes of Blocks from the blockchain.
            The lists starts with the block after the one with the "start_hash".
        """
        
        hashes = []
        index_start_block = 0
        index_stop_block = 0
        for index in range(len(self.blockchain.chain)):
            #print("Index = ", index, ". Kalkulierter Hash =", self.blockchain.chain[i].compute_hash() )
            if self.blockchain.chain[index].hash == start_hash:
                index_start_block = index+1
                exit
        if stop_hash == 0: # give all the headers
            index_stop_block = min(index_start_block + MAX_HEADERS_PER_MSG, len(self.blockchain.chain)) # 
            for index in range(index_start_block,index_stop_block):
                hashes.append(self.blockchain.chain[index].hash)
        return hashes

    def get_payload_for_get_blocks_msg(self):
        """
            Function that determins the best Blockchain. Therefore it searches the list of hashes in self.headers.
            The list that is chosen has to have two characteristics. 
                1. It has the highest correlation with other lists in self.headers
                2. It is the longest list of all lists that satisfy No. 1.
        """
        # create 2D Matrix where the Value stands for the first Index where the two lists differ

        #print("self.headers = ", self.headers)
        # if there are no new headers
        if self.headers == []:
            # Either it was forgotten to make a get_headers request or the request brought no new headers
            raise ValueError("Headers list is empty!")
        elif len(self.headers) == 1:
            raise ValueError("Headers list has to contain at least two lists.!")
        differ_index = np.zeros((len(self.headers),len(self.headers)))
        
        # indexes of the list that is compared to the other lists
        for index_list_1 in range(len(self.headers)):

            # index of the list that is currently compared to the first list
            for index_list_2 in range(index_list_1 + 1 , len(self.headers)): 
                
                # just compare all the items until there is a diffrence or one list ends
                num_of_items = min(len(self.headers[index_list_2]),len(self.headers[index_list_1]))
                for index_item_in_list in range(num_of_items):
                    if self.headers[index_list_1][index_item_in_list] != self.headers[index_list_2][index_item_in_list] or \
                            index_item_in_list == num_of_items-1:
                        
                        # write the index +1 of the diffrence to the matrix (two times because it is symmetrical)
                        differ_index[index_list_1][index_list_2] = index_item_in_list + 1
                        differ_index[index_list_2][index_list_1] = index_item_in_list + 1
                        break

        #print(differ_index)

        # find the best headers list. There are two criterias:
        
       
        # 1. the list has the most in common with other lists (=> sum of all diff_indexes is maximum)
        summed_values = [sum(i) for i in differ_index]
        #print("Summe übereinstimmungen =", summed_values)
        
        abs_max = max(summed_values)

        max_indexes = []
        while max(summed_values) == abs_max:
            max_indexes.append(summed_values.index(abs_max))
            if max(summed_values) == 0:
                return []
                #raise ValueError("The provided headers are all completely diffrent!")
            summed_values[max_indexes[-1]] = 0

        len_of_max_index_lists = [len(self.headers[i]) for i in max_indexes]
        #print("Laenge der besten Listen: ",len_of_max_index_lists)
        
        # 2. it is the longest list of all lists that satisfy 1.
        best_headers_list_index = max_indexes[len_of_max_index_lists.index(max(len_of_max_index_lists))]
        #print("Best and longest list is: ", best_headers_list_index) 
              
        payload = []
        for hash_ in self.headers[best_headers_list_index]:
            payload.append(('block',hash_))
        
        # reset the headers list for the next syncing 

        self.headers = []
        return payload #, best_headers_list_index


    def get_payload_for_block_msg(self,block_hash):
        """
            Returns the block-object corresponding to the provided block_hash.
        """
        
        payload = None
        for block in self.blockchain.chain:
            if block.hash == block_hash:
                payload = block
                exit
        return payload

    def get_message_created(self,receiver,payload, parser_type = 'type_default', message_type = None):
        """
            Creates a message object with the provided content.
            Adds automatically a md5 hash as checksum.
        """
        checksum = md5(str(payload).encode()).hexdigest()
        message = Message(sender=self.name,receiver=receiver, 
                        parser_type=parser_type,
                        message_type=message_type, 
                        payload=payload,
                        checksum=checksum)
        return message
    
    def handle_get_headers_msg(self,get_headers_msg):
        """
            Returns a message object containing all hashes of the blocks 
            between the start and stop hash.
        """
        
        # retrieve start and stop hash from message
        start_hash = get_headers_msg.payload[0]
        stop_hash = get_headers_msg.payload[1]
        # create a headers_msg as a response
        payload = self.get_payload_for_headers_msg(start_hash,stop_hash)

        # Built Message
        message = Message(sender=self.name,
                            receiver=get_headers_msg.sender,
                            parser_type='type_default',
                            message_type='headers_msg',
                            payload=payload,
                            checksum=get_checksum(payload))

        return message

    def handle_headers_msg(self,get_headers_msg):
        """
            Safes the headers to self.headers list
        """
        # create a get_blocks_msg as a response

        self.headers.append(get_headers_msg.payload)
         
        return None


    def handle_get_blocks_msg(self, get_headers_msg):
        """
            Creates and returns a block_msg as a response.
            This Message contains a list of all the blocks corresponding to the hash list provided.
        """
        # Workaround to send all the requested blocks. Should be in seperate messages but is now done by one message with a list
        payload = []
        for hash_chain in [x[1] for x in get_headers_msg.payload]:
            payload.append(self.get_payload_for_block_msg(hash_chain))
        #message = self.get_message_created(receiver=get_headers_msg[0],payload=payload,message_type='block_msg')

        message = Message(sender=self.name,
                    receiver=get_headers_msg.sender,
                    parser_type='type_chain',
                    message_type='block_msg',
                    payload=payload,
                    checksum=get_checksum(payload))

        return message

    def handle_block_msg(self, block_msg):
        """
            Retrieves all blocks from the block message and checks if it is a valid blockchain and fits to the current one.
            If everything is alright it  appends the blocks to the blockchain.
        """
        # check the validity of the blockchain
        chain = block_msg.payload

        is_valid_chain = Blockchain.check_chain_validity(chain=chain,previous_hash=self.blockchain.last_block.hash)
        if is_valid_chain:
            for block in block_msg.payload: 
                self.blockchain.chain.append(block)
        else:
            ValueError("The provided Blockchain does not match to the current chain, Chain invalid.")
        return None

    def handle_incoming_message(self,incoming_message):
        """
            Function to handle all messages regarding Blockchain synchronisation.
            Calls the message handler depending on the messae_type in a switch case statement.
        """
        message_checksum = md5(str(incoming_message.payload).encode()).hexdigest()
        return_message = None 

        #if message_checksum == incoming_message.checksum: # Check if Message was received correctly
        if True: # Check if Message was received correctly
            if incoming_message.message_type=='get_headers_msg':
                return_message = self.handle_get_headers_msg(incoming_message)
            
            elif incoming_message.message_type=='headers_msg':
                self.handle_headers_msg(incoming_message)
            
            elif incoming_message.message_type=='get_blocks_msg':
                return_message = self.handle_get_blocks_msg(incoming_message)
            
            elif incoming_message.message_type=='block_msg':
                self.handle_block_msg(incoming_message)
                return_message = None            
            
            else:
                print("Incoming message has unknown message Type!") # Undefined Message Type received
        else:
            print("Checksum of incoming message did not match!") # False Checksum, message was not received correctly
        return return_message
    # Blockchain synchronisation part END

    def get_chain(self):
        return self.blockchain.chain

    def create_signature(self, payload):
        byte_payload = str(payload).encode('utf-8')
        signature = self.__private_key.sign(
            byte_payload,
            padding.PSS(
                mgf=padding.MGF1(SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            SHA256()
        )
        integer_signature = [signature[i] for i in range(len(signature))]
        return integer_signature

    def check_signature(self, user, payload):
        # True if signature is correct
        # False if signature is not correct

        # get public key out of known public keys if existing
        public_key = self.get_user_public_key(user=user)
        
        if public_key==None:
            return False

        # convert the int signature to a byte signature
        integer_signature = payload['signature']
        new_signature_array = [value.to_bytes(1, 'big') for value in integer_signature]
        new_signature = b""
        for value  in new_signature_array:
            new_signature = new_signature + value

        # convert payload to bytes for signature check
        payload.pop("signature")
        byte_payload = str(payload).encode('utf-8')
        
        try:
            public_key.verify(
                new_signature,
                byte_payload,
                padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                SHA256()
            )
        except InvalidSignature:
            return False

        else:
            return True


    def write_backup(self):
        if os.path.exists(self.backup_path) and os.path.getsize(self.backup_path) > 0:
            os.remove(self.backup_path)

        json_obj = {
            "Name":        self.name,
            "Blockchain":  self.json_parser.parse_chain_to_dump(self.blockchain.chain),
            "Keys":        self.json_parser.parse_keys_dict_to_dump(self.user_public_key_map)
        }

        with open(self.backup_path, "w") as f:
            json.dump(json_obj,f)

    def read_backup(self):
        # Check Text-File already Exists and isn't empty
        if os.path.exists(self.backup_path) and os.path.getsize(self.backup_path) > 0:
            with open(self.backup_path, "r") as f:
                json_obj = json.loads(f.read())

                self.name = json_obj["Name"]
                self.blockchain.chain = self.json_parser.parse_dump_to_chain(json_obj["Blockchain"])
                self.user_public_key_map = self.json_parser.parse_dump_to_keys_dict(json_obj["Keys"])
            return True
        else:
            return False

    def print_chain(self, pretty=True):
        chain_data = []
        for block in self.blockchain.chain:
            chain_data.append(block.__dict__)

        if pretty == True:
            for block in chain_data:
                print("Block: ", block['index'])
                for elements in block:
                    print(" ", elements, ": ", block[elements])
                print()
                print()
        else:
            print(chain_data)

    def print_balance(self):
        balance = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == self.name:
                balance-= block.transactions.amount
            
            elif block.transactions.receiver == self.name:
                balance+= block.transactions.amount
        print(balance)

    def print_quotes(self, product):
        quantity = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == self.name and block.transactions.product == product:
                quantity+= block.transactions.quantity
            
            elif block.transactions.receiver == self.name and block.transactions.product == product:
                quantity-= block.transactions.quantity
        print(product, ": ", quantity)
    
