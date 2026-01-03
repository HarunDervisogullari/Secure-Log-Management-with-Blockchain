import json
import hashlib
import time
import base64
import os
import requests
import hvac
from eth_account import Account
from web3 import Web3
from datetime import datetime
# ==========================================
# ⚙️ CONFIGURATION (FILL THIS AREA)
# ==========================================

# 1. Blockchain Config
RPC_URL = "http://127.0.0.1:8545"  # Local Hardhat Network
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3" # <--- BURAYA DEPLOY ETTİĞİN ADRESİ YAPIŞTIR (Örn: 0x5FbDB...)
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Hardhat Account #0 Private Key (Sabittir)

# 2. Vault Config
VAULT_URL = "http://127.0.0.1:8200"
VAULT_TOKEN = "PASTE VAULT ROOT TOKEN HERE"
KEY_NAME = "log-master-key"

# 3. Pinata (IPFS) Config
PINATA_API_KEY = "PINATA API KEY"
PINATA_SECRET_API_KEY = "PINATA SECRET KEY" 

# ==========================================

def calculate_sha256(data):
    """Calculates SHA-256 hash of the input data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def encrypt_with_vault(plaintext, log_id):  # log_id parametresi eklendi
    """Encrypts data using a UNIQUE key for this log (Per-Log Key)."""
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    if not client.is_authenticated():
        raise Exception("Vault authentication failed.")
    
    # DYNAMIC KEY NAME: Each log will have its own key 
    # Ex: key-log-1767315158
    unique_key_name = f"key-{log_id}"
    
    # 1. First create this key in Vault (It will not give an error if it exists, it is idempotent) 
    try:
        client.secrets.transit.create_key(name=unique_key_name)
    except:
        pass # If the key already exists, continue

    # 2. Base64 conversion
    encoded_text = base64.b64encode(plaintext.encode('utf-8')).decode('ascii')
    
    # 3. Encrypt with that private key
    encrypt_response = client.secrets.transit.encrypt_data(
        name=unique_key_name,
        plaintext=encoded_text
    )
    return encrypt_response['data']['ciphertext']

def upload_to_pinata(encrypted_data, filename):
    """Uploads encrypted string to IPFS via Pinata."""
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    
    # Create a temporary file to upload (Pinata expects a file-like object)
    headers = {
        'pinata_api_key': PINATA_API_KEY,
        'pinata_secret_api_key': PINATA_SECRET_API_KEY
    }
    
    files = {
        'file': (filename, encrypted_data)
    }
    
    response = requests.post(url, files=files, headers=headers)
    
    if response.status_code == 200:
        return response.json()['IpfsHash']
    else:
        raise Exception(f"Pinata Upload Failed: {response.text}")

def write_to_blockchain(log_id, source_id, log_hash, ipfs_cid):
    """Writes the metadata to the Ethereum Blockchain."""
    # 1. Make the Connection
    w3 = Web3(Web3.HTTPProvider(RPC_URL))

    if not w3.is_connected():
        raise Exception("Failed to connect to Blockchain.")

    # 2. Upload ABI File
    with open("artifacts/contracts/LogNotary.sol/LogNotary.json", "r") as f:
        contract_json = json.load(f)
        contract_abi = contract_json["abi"]

    # 3. Create Contract Object
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

    # 4. Load Account (ERROR WAS HERE, FIXED) 
    # Instead of w3.eth.account we use the Account class directly
    account = Account.from_key(PRIVATE_KEY)
    print(f" 👤 Using Account: {account.address}")
    # 5. Prepare Transaction
    tx = contract.functions.recordLog(
        log_id,
        source_id,
        log_hash,
        ipfs_cid
    ).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 3000000,
        'gasPrice': w3.to_wei('1', 'gwei')
    })

    # 6. Sign Transaction
    signed_tx = Account.sign_transaction(tx, PRIVATE_KEY)

    # 7. Send to Network
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    # 8. Wait for Approval
    print(f"   Waiting for transaction confirmation... (Tx: {tx_hash.hex()})")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    return receipt

# ==========================================
# MAIN EXECUTION FLOW
# ==========================================
if __name__ == "__main__":
    print(" Starting Secure Log Agent...")
    
    # 1. Simulate a Log Entry
    log_id = f"log-{int(time.time())}" # Unique ID based on time
    source_id = "WebServer-01"
    original_log = f"CRITICAL: Unauthorized access attempt detected from 192.168.1.100 at {datetime.now()}"
    
    print(f"\n New Log Generated: {original_log}")
    print(f" Log ID: {log_id}")
    
    try:
        # 2. Hashing (Integrity Proof)
        log_hash = calculate_sha256(original_log)
        print(f"Element 1 (Hash): {log_hash}")
        
        # 3. Encryption (Privacy/GDPR)
        print(" Encrypting with Vault...")
        ciphertext = encrypt_with_vault(original_log, log_id)
        print(f"   Ciphertext: {ciphertext[:50]}...")
        
        # 4. Storage (IPFS)
        print("Pg Uploading to Pinata (IPFS)...")
        ipfs_cid = upload_to_pinata(ciphertext, f"{log_id}.enc")
        print(f"Element 2 (CID): {ipfs_cid}")
        
        # 5. Notarization (Blockchain)
        print("⛓️  Writing to Blockchain...")
        receipt = write_to_blockchain(log_id, source_id, log_hash, ipfs_cid)
        
        print("\n SUCCESS! Log Notarized.")
        print(f"   Block Number: {receipt['blockNumber']}")
        print(f"   Gas Used: {receipt['gasUsed']}")
        print("   Status: 1 (OK)")
        
    except Exception as e:
        print(f"\n ERROR: {str(e)}")