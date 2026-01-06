import json
import hashlib
import time
import base64
import os
import requests
import hvac
import paramiko
from eth_account import Account
from web3 import Web3
from datetime import datetime

# ==========================================
#  CONFIGURATION (BURAYI KONTROL ET!)
# ==========================================

# VM SSH INFORMATION (Ubuntu Login Information)
VM_IP = "192.168.145.130"    # <-- VM IP address
VM_SSH_USER = "USER NAME FOR UBUNTU"     # <-- Ubuntu username
VM_SSH_PASS = "1"            # <-- Ubuntu login password
LOG_PATH = "/var/ossec/logs/alerts/alerts.json"

# Blockchain Config
RPC_URL = "http://127.0.0.1:8545"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3" # It should be the same as Verify.py.
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Vault Config
VAULT_URL = "http://127.0.0.1:8200"
VAULT_TOKEN = "PASTE VAULT ROOT TOKEN HERE" # It should be the same as Verify.py.
KEY_NAME = "log-master-key"

# Pinata Config
PINATA_API_KEY = "PINATA API KEY"
PINATA_SECRET_API_KEY = "PINATA SECRET KEY" 

# ==========================================
# SSH LOG WATCHER CLASS
# ==========================================
class SSHLogWatcher:
    def __init__(self, host, user, password, remote_path):
        self.host = host
        self.user = user
        self.password = password
        self.remote_path = remote_path
        self.client = None

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.user, password=self.password)
            print(f" SSH Connection Established to {self.host}")
            return True
        except Exception as e:
            print(f" SSH Connection Failed: {e}")
            return False

    def tail_f(self):
        """Remote 'tail -f' komutunu calistirir."""
        # -n 0 : Only retrieve NEW rows (Do not retrieve past rows, avoid red errors)
        command = f"tail -n 0 -f {self.remote_path}"
        stdin, stdout, stderr = self.client.exec_command(command, get_pty=True)
        
        for line in iter(stdout.readline, ""):
            yield line

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def calculate_sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def encrypt_with_vault(plaintext, log_id):
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    unique_key_name = f"key-{log_id}"
    try: client.secrets.transit.create_key(name=unique_key_name)
    except: pass
    encoded_text = base64.b64encode(plaintext.encode('utf-8')).decode('ascii')
    encrypt_response = client.secrets.transit.encrypt_data(name=unique_key_name, plaintext=encoded_text)
    return encrypt_response['data']['ciphertext']

def upload_to_pinata(encrypted_data, filename):
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {'pinata_api_key': PINATA_API_KEY, 'pinata_secret_api_key': PINATA_SECRET_API_KEY}
    files = {'file': (filename, encrypted_data)}
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200: return response.json()['IpfsHash']
    else: raise Exception(f"Pinata Error: {response.text}")

def write_to_blockchain(log_id, source_id, log_hash, ipfs_cid):
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    with open("artifacts/contracts/LogNotary.sol/LogNotary.json", "r") as f:
        contract_abi = json.load(f)["abi"]
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
    account = Account.from_key(PRIVATE_KEY)
    
    tx = contract.functions.recordLog(log_id, source_id, log_hash, ipfs_cid).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 3000000,
        'gasPrice': w3.to_wei('1', 'gwei')
    })
    signed_tx = Account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    time.sleep(1)
    return receipt
    return w3.eth.wait_for_transaction_receipt(tx_hash)

# ==========================================
# MAIN EXECUTION FLOW
# ==========================================
if __name__ == "__main__":
    print(" Starting Secure Log Agent (SSH Live Stream Mode)...")
    
    # 1. SSH Connection
    watcher = SSHLogWatcher(VM_IP, VM_SSH_USER, VM_SSH_PASS, LOG_PATH)
    if not watcher.connect():
        exit()

    print(" Watching remote logs... (Waiting for NEW alerts)")
    print(" ACTION: Go to VM and run: 'ssh admin@localhost' (fail password)")

    try:
        # 2.Listen to the Live Stream
        for line in watcher.tail_f():
            try:
                line = line.strip()
                if not line: continue
                
                # Sadece JSON satirlarini al
                if not line.startswith("{"): continue

                alert = json.loads(line)

                # ---  NOISE FILTER  ---
                # Only process logs of Level 5 and above (containing threats).
                # Block routine Linux messages (Level 3-4).
                if alert['rule']['level'] < 5:
                    continue
                # ------------------------------
                
                # Extract Data
                rule_desc = alert['rule']['description']
                src_ip = alert.get('data', {}).get('src_ip', 'Internal/VM')
                timestamp = alert['timestamp']
                log_id = f"wazuh-{alert['id']}"
                
                original_log = f"WAZUH_ALERT: {rule_desc} from {src_ip} at {timestamp}"
                
                print(f"\n LIVE ALERT DETECTED! (Level {alert['rule']['level']})")
                print(f"    Log ID: {log_id}")
                print(f"    {original_log}")
                
                # --- Blockchain and IPFS Streaming ---
                print("    Encrypting & Notarizing...")
                
                log_hash = calculate_sha256(line.strip())
                ciphertext = encrypt_with_vault(original_log, log_id)
                ipfs_cid = upload_to_pinata(ciphertext, f"{log_id}.enc")
                receipt = write_to_blockchain(log_id, "Wazuh-SSH", log_hash, ipfs_cid)
                
                print(f"    SUCCESS! Block: {receipt['blockNumber']}")
                print("    Waiting for next CRITICAL alert...")
                
            except json.JSONDecodeError:
                continue 
            except Exception as e:
                print(f"    Transaction Info: {e}")

    except KeyboardInterrupt:
        print("\n Agent stopped.")
        if watcher.client: watcher.client.close()