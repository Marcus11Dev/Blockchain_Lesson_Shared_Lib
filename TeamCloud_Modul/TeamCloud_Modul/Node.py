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
        self.user_public_key_map = {}

        self.blockchain=Blockchain()
        self.json_parser = JSON_Parser()

        self.blockchain.create_genesis_block()
            
        self.balance = 0
        self.update_balance()         
        
        self.headers = [] # List containing the payload of headers messages (list of hashes)
    
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

    def check_transaction_validity(self, transaction: Transaction):
        
        if transaction.sender != "Cloud" and transaction.sender != "bank":
            # Check buyer has enough money
            print("Check Buy quotes")
            print(f"Balance of {transaction.sender}",self.get_balance_of(transaction.sender))
            if self.get_balance_of(transaction.sender) < transaction.amount:
                return False

        if transaction.receiver != "Cloud":
            # Check seller has enough quantity
            print("Check Sell quotes")
            print(f"Balance of {transaction.receiver}",self.get_quotes_of(transaction.receiver, transaction.product))
            if self.get_quotes_of(transaction.receiver, transaction.product) < transaction.quantity:
                return False

        return True
    
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

    def get_user_public_key(self, user,temp_user_public_key_map ={}):
        try:
            print("user public key map",self.user_public_key_map)
            print()
            print("user public key map",self.user_public_key_map[user])
            return serialization.load_pem_public_key(self.user_public_key_map[user].encode('ascii'))
        except Exception as e:
            print(e)
            try: 
                return serialization.load_pem_public_key(temp_user_public_key_map[user].encode('ascii'))
            except:
                return None

        
    def transaction(self,transaction):
        if transaction.product == 'InitCoin':
            self.add_to_user_public_key_map(user=transaction.receiver,public_key=transaction.signature)
        self.blockchain.add_new_transaction(transaction)
        self.blockchain.mine()


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

    def _get_payload_for_headers_msg(self,start_hash,stop_hash):
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

        # if there are no new headers
        if self.headers == []:
            # Either it was forgotten to make a get_headers request or the request brought no new headers
            raise ValueError("Headers list is empty!")
        elif len(self.headers) == 1:
            raise ValueError("Headers list has to contain at least two lists.!")
        
        best_headers_list_index = self._get_best_headers_list_index()
        payload = []
        for hash_ in self.headers[best_headers_list_index]:
            payload.append(('block',hash_))
        
        # reset the headers list for the next syncing 

        self.headers = []
        return payload #, best_headers_list_index

    def _get_best_headers_list_index(self):
        differ_index = self._get_differ_index_array_with_headers_list()
        # find the best headers list. There are two criterias:
               
        # 1. the list has the most in common with other lists (=> sum of all diff_indexes is maximum)
        summed_values = [sum(i) for i in differ_index]
        #print("Summe übereinstimmungen =", summed_values)
        
        abs_max = max(summed_values)

        max_indexes = []
        while max(summed_values) == abs_max:
            max_indexes.append(summed_values.index(abs_max))
            if max(summed_values) == 0:
                return 0
            summed_values[max_indexes[-1]] = 0

        len_of_max_index_lists = [len(self.headers[i]) for i in max_indexes]
        
        # 2. it is the longest list of all lists that satisfy 1.
        best_headers_list_index = max_indexes[len_of_max_index_lists.index(max(len_of_max_index_lists))]
        return best_headers_list_index

    def _get_differ_index_array_with_headers_list(self):
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
        return differ_index


    def _get_payload_for_block_msg(self,block_hash):
        """
            Returns the block-object corresponding to the provided block_hash.
        """
        
        payload = None
        for block in self.blockchain.chain:
            if block.hash == block_hash:
                payload = block
                exit
        return payload
    
    def _handle_get_headers_msg(self,get_headers_msg):
        """
            Returns a message object containing all hashes of the blocks 
            between the start and stop hash.
        """
        
        # retrieve start and stop hash from message
        start_hash = get_headers_msg.payload[0]
        stop_hash = get_headers_msg.payload[1]
        # create a headers_msg as a response
        payload = self._get_payload_for_headers_msg(start_hash,stop_hash)

        # Built Message
        message = Message(sender=self.name,
                            receiver=get_headers_msg.sender,
                            parser_type='type_default',
                            message_type='headers_msg',
                            payload=payload,
                            checksum=get_checksum(payload))

        return message

    def _handle_headers_msg(self,get_headers_msg):
        """
            Safes the headers to self.headers list
        """
        # create a get_blocks_msg as a response

        self.headers.append(get_headers_msg.payload)
         
        return None


    def _handle_get_blocks_msg(self, get_headers_msg):
        """
            Creates and returns a block_msg as a response.
            This Message contains a list of all the blocks corresponding to the hash list provided.
        """
        # Workaround to send all the requested blocks. Should be in seperate messages but is now done by one message with a list
        payload = []
        for hash_chain in [x[1] for x in get_headers_msg.payload]:
            payload.append(self._get_payload_for_block_msg(hash_chain))

        message = Message(sender=self.name,
                    receiver=get_headers_msg.sender,
                    parser_type='type_chain',
                    message_type='block_msg',
                    payload=payload,
                    checksum=get_checksum(payload))

        return message

    def _handle_block_msg(self, block_msg):
        """
            Retrieves all blocks from the block message and checks if it is a valid blockchain and fits to the current one.
            If everything is alright it  appends the blocks to the blockchain.
        """
        # check the validity of the blockchain
        chain = block_msg.payload
        self.append_chain_to_own_blockchain(chain=chain)      
        return None

    def append_chain_to_own_blockchain(self,chain):
        if self.are_signatures_correct_and_chain_valid(chain=chain):
            self.user_public_key_map.update(self._get_temp_user_public_key_map(chain=chain))
            for block in chain: 
                self.blockchain.chain.append(block)
        else:
            ValueError("The provided Blockchain does not match to the current chain, Chain invalid.")

    def are_signatures_correct_and_chain_valid(self,chain):
        is_valid_chain = Blockchain.check_chain_validity(chain=chain,previous_hash=self.blockchain.last_block.hash)
        all_signatures_correct = self._all_signatures_correct(chain=chain)
        return is_valid_chain and all_signatures_correct

    def _all_signatures_correct(self,chain):
        temp_user_public_key_map =self._get_temp_user_public_key_map(chain=chain)
        for block in chain:
            if not block.transactions.product == 'InitCoin':
                user = self._get_user_involved_in_transaction(block=block)
                signature = block.transactions.signature
                product = block.transactions.product
                quantity = block.transactions.quantity
                payload={'product':product,'quantity':quantity,'signature':signature}
                if not self.check_signature(user=user,payload=payload,temp_user_public_key_map=temp_user_public_key_map):
                    return False
        return True

    def _get_temp_user_public_key_map(self,chain):
        temp_user_public_key_map ={}
        for block in chain:
            if block.transactions.product == 'InitCoin':
                user = block.transactions.receiver
                pub_key = block.transactions.signature.encode('utf-8')
                temp_user_public_key_map.update({user:pub_key})
        return temp_user_public_key_map

    def _get_user_involved_in_transaction(self,block):
        sender = block.transactions.sender
        receiver = block.transactions.receiver
        if  sender != 'Cloud' and sender != 'bank':
            return sender
        elif  receiver != 'Cloud' and receiver != 'bank':
            return receiver
        else:
            raise ValueError("Block contains no user involved")


    def handle_incoming_message(self,incoming_message):
        """
            Function to handle all messages regarding Blockchain synchronisation.
            Calls the message handler depending on the messae_type in a switch case statement.
        """
        message_checksum = md5(str(incoming_message.payload).encode()).hexdigest()
        return_message = None 
        if incoming_message.message_type=='get_headers_msg':
            return_message = self._handle_get_headers_msg(incoming_message)
        
        elif incoming_message.message_type=='headers_msg':
            self._handle_headers_msg(incoming_message)
        
        elif incoming_message.message_type=='get_blocks_msg':
            return_message = self._handle_get_blocks_msg(incoming_message)
        
        elif incoming_message.message_type=='block_msg':
            self._handle_block_msg(incoming_message)
            return_message = None            
        
        else:
            print("Incoming message has unknown message Type!") # Undefined Message Type received
        return return_message
    # Blockchain synchronisation part END

    # def get_chain(self):
    #     return self.blockchain.chain

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

    def check_signature(self, user, payload, temp_user_public_key_map ={}):
        # True if signature is correct
        # False if signature is not correct

        # get public key out of known public keys if existing
        print()
        print("In Signature")
        public_key = self.get_user_public_key(user=user,temp_user_public_key_map=temp_user_public_key_map)
        if public_key==None:
            print("Could not find public key")
            return False

        # convert the int signature to a byte signature
        integer_signature = payload['signature']
        new_signature_array = [value.to_bytes(1, 'big') for value in integer_signature]
        new_signature = b""
        for value  in new_signature_array:
            new_signature = new_signature + value
        print("test1")
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
            print("Signature check failed")
            return False

        else:
            print("Signature Check worked")
            return True




    def create_user_public_key_map(self):
        # Init user-key map
        self.user_public_key_map = {}

        try:
            # Loop through chain
            for block in self.blockchain.chain:
                if block.transactions.product == 'InitCoin':
                    user = block.transactions.receiver
                    pub_key = block.transactions.signature.encode('utf-8')
                    
                    if user in self.user_public_key_map or user=="Cloud":
                        continue

                    # Add user-key pair
                    self.user_public_key_map.update({user:pub_key})

        except:
            print("Error occured creating user-key map")

    ####################################################################
    # Agent: Print Functions
    ####################################################################

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

    def print_balance(self, all=False):
        user_list = {}

        # Set user_list
        if all:
            for user in self.user_public_key_map:
                if user != "Cloud":
                    user_list.update({user : 0})
        else:
            user_list.update({self.name:0})
        
        # Set balances
        for block in self.blockchain.chain:
            if block.transactions.sender in user_list:
                user_list[block.transactions.sender] -= block.transactions.amount
            
            elif block.transactions.receiver in user_list:
                user_list[block.transactions.receiver] += block.transactions.amount

        # Print balances
        for user in user_list:
            print(user, ": ", user_list[user]) 

    def print_quotes(self, product):
        quantity = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == self.name and block.transactions.product == product:
                quantity+= block.transactions.quantity
            
            elif block.transactions.receiver == self.name and block.transactions.product == product:
                quantity-= block.transactions.quantity
        print(product, ": ", quantity)

    ####################################################################
    # Agent: Get Functions
    ####################################################################

    def get_balance(self, all=False):
        user_list = {}

        # Set user_list
        if all:
            for user in self.user_public_key_map:
                if user != "Cloud":
                    user_list.update({user : 0})
        else:
            user_list.update({self.name:0})
        
        # Set balances
        for block in self.blockchain.chain:
            if block.transactions.sender in user_list:
                user_list[block.transactions.sender] -= block.transactions.amount
            
            elif block.transactions.receiver in user_list:
                user_list[block.transactions.receiver] += block.transactions.amount

        # Return balances
        return user_list

    def get_quotes(self, product):
        quantity = 0
        for block in self.blockchain.chain:
            if block.transactions.sender == self.name and block.transactions.product == product:
                quantity+= block.transactions.quantity
            
            elif block.transactions.receiver == self.name and block.transactions.product == product:
                quantity-= block.transactions.quantity
        
        return {"Product": product, "Quantity": quantity}