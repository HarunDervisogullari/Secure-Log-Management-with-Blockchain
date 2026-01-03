import json
from web3 import Web3
from datetime import datetime

# ==========================================
# SETTINGS
# ==========================================
RPC_URL = "http://127.0.0.1:8545"
# PASTE THE CORRECT ADDRESS FROM agent.py HERE:
CONTRACT_ADDRESS = "0x..." 
# ==========================================

def view_all_logs():
    print("📡 Connecting to Blockchain...")
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    if not w3.is_connected():
        print(" Failed to connect to Hardhat Network.")
        return

    # Load ABI
    with open("artifacts/contracts/LogNotary.sol/LogNotary.json", "r") as f:
        contract_abi = json.load(f)["abi"]
    
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

    print(f"🔍 Scanning Blockchain history for 'LogNotarized' events...\n")

    # Create Event Filter (from block 0 to the latest block)
    # Fetches LogNotarized events
    event_filter = contract.events.LogNotarized.create_filter(fromBlock=0, toBlock='latest')
    all_events = event_filter.get_all_entries()

    if len(all_events) == 0:
        print(" No logs found on the blockchain yet.")
        return

    print(f" Found {len(all_events)} records:\n")
    print("-" * 80)
    
    for event in all_events:
        args = event['args']
        log_id = args['logId']
        source = args['sourceId']
        ipfs_cid = args['ipfsCid']
        timestamp = args['timestamp']
        
        # Convert timestamp to a human-readable date
        dt_object = datetime.fromtimestamp(timestamp)
        
        print(f" Time:   {dt_object}")
        print(f" Log ID: {log_id}")
        print(f" Source: {source}")
        print(f" IPFS:   {ipfs_cid}")
        print(f" Tx Hash: {event['transactionHash'].hex()}")
        print("-" * 80)

if __name__ == "__main__":
    view_all_logs()
