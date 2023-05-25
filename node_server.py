import base64
import os
import sys
import signal
import atexit
from hashlib import sha256
import json
import time
import binascii
from flask import Flask, request
import requests

from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding

port=8000
class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
        
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    difficulty = 2

    def __init__(self, chain=None):
        self.unconfirmed_transactions = []
        self.chain = chain
        if self.chain is None:
            self.chain = []
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            raise ValueError("Hash  Invalido")

        if not Blockchain.is_valid_proof(block, proof):
            raise ValueError("Prueba invalida")

        block.hash = proof
        self.chain.append(block)

    @staticmethod
    def proof_of_work(block):
        
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break
            for transaction in block.transactions:
                transaction_content = transaction['content']  # Obtener el contenido de la transacción
                signature = transaction['pass']
                public_key = transaction['public'] 
                if not verify_signature(public_key, transaction_content.encode(), signature):
                    result = False
                    break
                if not result:
                    break
 
            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):
        
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True


app = Flask(__name__)

blockchain = None

peers = set()

@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["author", "content"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Transacion Invalida", 404

    tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "Success", 201


chain_file_name = os.environ.get('DATA_FILE')


def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  # skip genesis block
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        generated_blockchain.add_block(block, proof)
    return generated_blockchain

@app.route('/chain', methods=['GET'])
def get_chain():
    print("Getting chain")
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})


def save_chain():
    if chain_file_name is not None:
        with open(chain_file_name, 'w') as chain_file:
            chain_file.write(get_chain())


def exit_from_signal(signum, stack_frame):
    sys.exit(0)


atexit.register(save_chain)
signal.signal(signal.SIGTERM, exit_from_signal)
signal.signal(signal.SIGINT, exit_from_signal)


if chain_file_name is None:
    data = None
else:
    with open(chain_file_name, 'r') as chain_file:
        raw_data = chain_file.read()
        if raw_data is None or len(raw_data) == 0:
            data = None
        else:
            data = json.loads(raw_data)

if data is None:
    blockchain = Blockchain()
else:
    blockchain = create_chain_from_dump(data['chain'])
    peers.update(data['peers'])


def verify_signature(public_base64, message, signature_hex):
    try:
        public_bytes = base64.b64decode(public_base64)
        public_key = serialization.load_der_public_key(public_bytes)
        signature = binascii.unhexlify(signature_hex)
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return None
    
@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "Nada para minar"
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            
                announce_new_block(blockchain.last_block)
                return "Bloque numero {} minado.".format(blockchain.last_block.index)
        else:
                return "El Bloque numero {} No se añade!!!!.".format(blockchain.last_block.index)

@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Datos invalidos", 400
    peers.add(node_address)
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Datos invaloidos", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers

        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        return response.content, response.status_code

@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    try:
        blockchain.add_block(block, proof)
    except ValueError as e:
        return "El bloque fue descartado por el nodo: " + e.str(), 400

    return "Bloque añadido a la cadena", 201

@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)


def consensus():
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block):
    
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)

#app.run(debug=True, port=8000)
