import time
import hashlib
import json
import requests
import base64
from flask import Flask, request
from multiprocessing import Process, Pipe
import ecdsa

from miner_config import MINER_ADDRESS, MINER_NODE_URL, PEER_NODES

node = Flask(__name__)

# Define the desired mining interval in seconds
MINING_INTERVAL = 1

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        sha = hashlib.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode('utf-8'))
        return sha.hexdigest()


def create_genesis_block():
    return Block(0, time.time(), {
        "proof-of-work": 9,
        "transactions": None},
        "0")


BLOCKCHAIN = [create_genesis_block()]

NODE_PENDING_TRANSACTIONS = []


def proof_of_work(last_proof, blockchain):
    incrementer = last_proof + 1
    start_time = time.time()
    while not (incrementer % 7919 == 0 and incrementer % last_proof == 0):
        incrementer += 1
        if int((time.time()-start_time) % 60) == 0:
            new_blockchain = consensus(blockchain)
            if new_blockchain:
                return False, new_blockchain
    return incrementer, blockchain


def mine(a, blockchain, node_pending_transactions):
    BLOCKCHAIN = blockchain
    NODE_PENDING_TRANSACTIONS = node_pending_transactions
    last_block_time = time.time()  # Track the time when the last block was mined
    while True:
        current_time = time.time()
        if current_time - last_block_time >= MINING_INTERVAL:  # Check if it's time to mine a new block
            last_block = BLOCKCHAIN[-1]
            last_proof = last_block.data['proof-of-work']
            proof = proof_of_work(last_proof, BLOCKCHAIN)
            if not proof[0]:
                BLOCKCHAIN = proof[1]
                a.send(BLOCKCHAIN)
                continue
            else:
                if len(NODE_PENDING_TRANSACTIONS) > 0:  # Ensure there are pending transactions to include
                    new_block_data = {
                        "proof-of-work": proof[0],
                        "transactions": list(NODE_PENDING_TRANSACTIONS)
                    }
                    new_block_index = last_block.index + 1
                    new_block_timestamp = time.time()
                    last_block_hash = last_block.hash
                    NODE_PENDING_TRANSACTIONS = []
                    mined_block = Block(new_block_index, new_block_timestamp, new_block_data, last_block_hash)
                    BLOCKCHAIN.append(mined_block)
                    print(json.dumps({
                        "index": new_block_index,
                        "timestamp": str(new_block_timestamp),
                        "data": new_block_data,
                        "hash": last_block_hash
                    }, sort_keys=True) + "\n")
                    print("Coin mined successfully!")  # Print a message when a coin is mined
                    a.send(BLOCKCHAIN)
                    requests.get(url=MINER_NODE_URL + '/blocks', params={'update': MINER_ADDRESS})
                    last_block_time = current_time  # Update last block time
        # Sleep for a short duration to prevent high CPU usage
        time.sleep(0.1)


def find_new_chains():
    other_chains = []
    for node_url in PEER_NODES:
        block = requests.get(url=node_url + "/blocks").content
        block = json.loads(block)
        validated = validate_blockchain(block)
        if validated:
            other_chains.append(block)
    return other_chains


def consensus(blockchain):
    BLOCKCHAIN = blockchain
    other_chains = find_new_chains()
    longest_chain = BLOCKCHAIN
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    if longest_chain == BLOCKCHAIN:
        return False
    else:
        BLOCKCHAIN = longest_chain
        return BLOCKCHAIN


def validate_blockchain(block):
    return True


@node.route('/blocks', methods=['GET'])
def get_blocks():
    if request.args.get("update") == MINER_ADDRESS:
        global BLOCKCHAIN
        BLOCKCHAIN = pipe_input.recv()
    chain_to_send = BLOCKCHAIN
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "data": str(block.data),
            "hash": block.hash
        }
        chain_to_send_json.append(block)
    chain_to_send = json.dumps(chain_to_send_json, sort_keys=True)
    return chain_to_send


@node.route('/txion', methods=['GET', 'POST'])
def transaction():
    if request.method == 'POST':
        new_txion = request.get_json()
        if new_txion['coin'] == "JEWISHRATECOIN":  # Check coin type
            if validate_signature(new_txion['from'], new_txion['signature'], new_txion['message']):
                if len(NODE_PENDING_TRANSACTIONS) == 0:  # Ensure no pending transactions
                    NODE_PENDING_TRANSACTIONS.append(new_txion)
                    print("New transaction")
                    print("FROM: {0}".format(new_txion['from']))
                    print("TO: {0}".format(new_txion['to']))
                    print("AMOUNT: {0}\n".format(new_txion['amount']))
                    return "Transaction submission successful\n"
                else:
                    return "Pending transaction exists. Try again later\n"
            else:
                return "Transaction submission failed. Wrong signature\n"
        else:
            return "Invalid coin type\n"
    else:
        return "Transactions can only be submitted through the wallet"


def validate_signature(public_key, signature, message):
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, message.encode())
    except:
        return False


def welcome_msg():
    print("""       =========================================\n
        JEWISHRATECOIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/cosme12/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")


if __name__ == '__main__':
    welcome_msg()
    pipe_output, pipe_input = Pipe()
    miner_process = Process(target=mine, args=(pipe_output, BLOCKCHAIN, NODE_PENDING_TRANSACTIONS))
    miner_process.start()
    transactions_process = Process(target=node.run(), args=pipe_input)
    transactions_process.start()
