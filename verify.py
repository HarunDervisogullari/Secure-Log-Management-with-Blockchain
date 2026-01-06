import json
import base64
import requests
import hvac
import hashlib
import paramiko
from web3 import Web3

# ==========================================
#  CONFIGURATION (CHECK!)
# ==========================================
# 1. Blockchain Config
RPC_URL = "http://127.0.0.1:8545"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3" 

# 2. Vault Config
VAULT_URL = "http://127.0.0.1:8200"
VAULT_TOKEN = "PASTE VAULT ROOT TOKEN HERE" 

# 3. IPFS Gateway
IPFS_GATEWAY = "https://gateway.pinata.cloud/ipfs/"

# 4. VM SSH BILGILERI
VM_IP = "192.168.145.130"
VM_USER = "USER NAME FOR UBUNTU"
VM_PASS = "1"  
LOG_FILE_PATH = "/var/ossec/logs/alerts/alerts.json"

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def calculate_sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def get_local_raw_line(log_id):
    client = None
    try:
        search_id = log_id.replace("wazuh-", "")
        print(f"    Connecting to {VM_IP} to search for ID: {search_id}...")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(VM_IP, username=VM_USER, password=VM_PASS, timeout=5)
        
        cmd = f"grep '\"id\":\"{search_id}\"' {LOG_FILE_PATH}"
        stdin, stdout, stderr = client.exec_command(cmd)
        
        result = stdout.read().decode().strip()
        client.close()
        
        return result 

    except Exception as e:
        print(f" SSH Error: {e}")
        if client: client.close()
        return None

# ==========================================
# MAIN FUNCTION
# ==========================================
def verify_log_integrity(log_id_to_check):
    print(f"\n Verifying Log ID: {log_id_to_check}...")

    # --- 1. BLOCKCHAIN CHECK (METADATA) ---
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    try:
        with open("artifacts/contracts/LogNotary.sol/LogNotary.json", "r") as f:
            contract_abi = json.load(f)["abi"]
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
        log_data = contract.functions.getLog(log_id_to_check).call()
        
        ipfs_cid = None
        stored_blockchain_hash = None
        
        # Extract Hash and CID from Tuple
        for item in log_data:
            if str(item).startswith("Qm"): ipfs_cid = item
            elif len(str(item)) == 64: stored_blockchain_hash = item
            
        if not ipfs_cid: 
            print(" Log ID not found on Blockchain.")
            return

    except Exception as e:
        print(f" Blockchain Error: {e}")
        return

    # --- 2. IPFS & VAULT (GDPR & DECRYPTION CHECK) ---
    print(f"    Fetching encrypted data from IPFS...")
    try:
        response = requests.get(f"{IPFS_GATEWAY}{ipfs_cid}")
        if response.status_code != 200:
            print(" IPFS Fetch failed.")
            return
            
        encrypted_data = response.text
        client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
        key_name = f"key-{log_id_to_check}"
        
        # --- KRİTİK NOKTA: DECRYPTION & GDPR ---
        try:
            decrypt_response = client.secrets.transit.decrypt_data(
                name=key_name, 
                ciphertext=encrypted_data
            )
            # If it's here, it means the code has been cracked (The key is still there).
            plaintext_b64 = decrypt_response['data']['plaintext']
            blockchain_log_text = base64.b64decode(plaintext_b64).decode('utf-8')
            
            print(f"    Blockchain Record Verified (Readable).")
            print(f"    CONTENT: {blockchain_log_text}")

        except hvac.exceptions.InvalidPath:
            # We end up here if Vault gives a "No such key" error.
            print("\n ACCESS DENIED (GDPR COMPLIANCE)")
            print("===========================================================")
            print("     DATA IS UNREADABLE: DECRYPTION KEY DELETED.")
            print("   This log has been 'Crypto-Shredded' in accordance with")
            print("   Right to be Forgotten (Unutulma Hakkı).")
            print("===========================================================")
            return # If there is no content, the integrity check cannot be performed, log out.

    except Exception as e:
        print(f" Decryption Error: {e}")
        return

    # --- 3. LOCAL FILE CHECK & HASH COMPARISON (TAMPER CHECK) ---
    print("\n Comparing Cryptographic Hashes (Math Check)...")
    
    local_raw_line = get_local_raw_line(log_id_to_check)
    
    if local_raw_line:
        # CALCULATE HASH (RAW DATA)
        local_calculated_hash = calculate_sha256(local_raw_line)
        
        print(f"    Blockchain Hash: {stored_blockchain_hash}")
        print(f"    Local Raw Hash:  {local_calculated_hash}")
        
        if stored_blockchain_hash == local_calculated_hash:
            print("\n MATCH! The raw log line is 100% authentic.")
        else:
            print("\n TAMPER DETECTED! HASH MISMATCH! 🚨")
            print("   The local file content has been modified.")
            
    else:
        print(" Local log entry not found via SSH.")

if __name__ == "__main__":
    target_id = input("Enter Log ID to verify: ")
    verify_log_integrity(target_id.strip())