import json
import hashlib
import requests
import hvac
import base64
from web3 import Web3
from eth_account import Account

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
RPC_URL = "http://127.0.0.1:8545"
# PASTE THE CORRECT ADDRESS FROM agent.py HERE:
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3" 

# Vault Config
VAULT_URL = "http://127.0.0.1:8200"
VAULT_TOKEN = "PASTE VAULT ROOT TOKEN HERE" 
KEY_NAME = "log-master-key"

# ==========================================

def calculate_sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def get_log_from_blockchain(log_id):
    """Blockchain'den metadata'yı okur."""
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    with open("artifacts/contracts/LogNotary.sol/LogNotary.json", "r") as f:
        contract_abi = json.load(f)["abi"]
    
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
    
    # Call the getLog function 
    # Return: (sourceId, logHash, ipfsCid, timestamp)
    return contract.functions.getLog(log_id).call()

def download_from_ipfs(cid):
    """IPFS Gateway üzerinden şifreli dosyayı indirir."""
    # We can use Pinata's public gateway or public gateway
    gateway_url = f"https://gateway.pinata.cloud/ipfs/{cid}"
    print(f" 🌐 Downloading from IPFS: {gateway_url}")
    
    try:
        response = requests.get(gateway_url, timeout=10)
        if response.status_code == 200:
            return response.text # Returns ciphertext
        else:
            # Let's try an alternative gateway (sometimes pinata gateway can be slow)
            print("   (Pinata gateway slow, trying ipfs.io...)")
            response = requests.get(f"https://ipfs.io/ipfs/{cid}", timeout=10)
            if response.status_code == 200:
                return response.text
            else:
                raise Exception("Could not download from IPFS gateways.")
    except Exception as e:
        # If we cannot pull from the internet (Gateway issues), manual entry may be required for local testing 
        # But we're throwing errors for now.
        raise Exception(f"IPFS Download Error: {e}")

def decrypt_with_vault(ciphertext, log_id): # log_id parametresi eklendi
    """Vault kullanarak o loga özel anahtarla şifreyi çözer."""
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    
    # Derive key name from Log ID
    unique_key_name = f"key-{log_id}"
    
    decrypt_response = client.secrets.transit.decrypt_data(
        name=unique_key_name,  # Dinamik isim
        ciphertext=ciphertext
    )
    
    plaintext_b64 = decrypt_response['data']['plaintext']
    return base64.b64decode(plaintext_b64).decode('utf-8')

# ==========================================
# MAIN AUDIT PROCESS
# ==========================================
if __name__ == "__main__":
    print("🕵️‍♂️ Starting Auditor Verification Tool...")
    
    #WE ASK FOR LOG ID FROM THE USER 
    # You will enter the ID you just generated here. Ex: log-1767314122
    target_log_id = input("\n👉 Enter Log ID to verify: ")
    
    try:
        # 1. Blockchain Query
        print(f"\n🔗 Querying Blockchain for {target_log_id}...")
        record = get_log_from_blockchain(target_log_id)
        
        source_id = record[0]
        bc_hash = record[1]
        bc_cid = record[2]
        timestamp = record[3]
        
        print(f"    Found Record!")
        print(f"      Source: {source_id}")
        print(f"      Hash (On-Chain): {bc_hash}")
        print(f"      CID (On-Chain):  {bc_cid}")
        print(f"      Time: {timestamp}")
        
        # 2. IPFS Download
        print(f"\nPg Fetching Data from IPFS...")
        encrypted_data = download_from_ipfs(bc_cid)
        print(f"    Encrypted Data: {encrypted_data[:40]}...")
        
        # 3. Decryption (Vault)
        print(f"\n Decrypting via Vault...")
        decrypted_log = decrypt_with_vault(encrypted_data, target_log_id)
        print(f"    Decrypted Content: {decrypted_log}")
        
        # 4. Verification
        print(f"\n  Verifying Integrity...")
        current_hash = calculate_sha256(decrypted_log)
        
        print(f"   Calculated Hash: {current_hash}")
        print(f"   Blockchain Hash: {bc_hash}")
        
        if current_hash == bc_hash:
            print("\n INTEGRITY CONFIRMED! The log is authentic and unaltered.")
        else:
            print("\n INTEGRITY FAILURE! The log has been tampered with!")
            
    except Exception as e:
        print(f"\n Error during verification: {e}")
        print("Note: If IPFS download fails, it might be due to gateway latency. Wait a minute and try again.")