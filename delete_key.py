import hvac
import sys

# ==========================================
#  CONFIGURATION
# ==========================================
VAULT_URL = "http://127.0.0.1:8200"
VAULT_TOKEN = "PASTE VAULT ROOT TOKEN HERE" # <--- KONTROL ET

def crypto_shred_log(log_id):
    # Log ID cleanup (correct if the wazuh prefix exists or is missing)
    clean_id = log_id.strip()
    key_name = f"key-{clean_id}"

    print(f"\n  Initiating Crypto-Shredding for Log ID: {clean_id}")
    print(f"    Target Key: {key_name}")

    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)

    if not client.is_authenticated():
        print(" Vault Authentication Failed. Check token.")
        return

    try:
        # Check if the key exists (If not, it has already been deleted)
        try:
            client.secrets.transit.read_key(name=key_name)
        except hvac.exceptions.InvalidPath:
            print(f"  Key '{key_name}' not found. It might have been already deleted.")
            return

        # Unlock "Safety Unlock"
        client.secrets.transit.update_key_configuration(
            name=key_name,
            deletion_allowed=True
        )
        print(f"    Key unlocked for deletion...")

        # Now Delete (Permanently Delete)
        client.secrets.transit.delete_key(name=key_name)
        
        print("-------------------------------------------------------------")
        print(f"    SUCCESS: Key '{key_name}' PERMANENTLY DELETED.")
        print("     GDPR COMPLIANCE: The data on Blockchain is now unreadable.")
        print("    Right to be Forgotten (Unutulma Hakkı) Applied.")
        print("-------------------------------------------------------------")

    except Exception as e:
        print(f" Error during shredding process: {e}")

if __name__ == "__main__":
    target_id = input("Enter Log ID to DELETE (Warning: Irreversible!): ")
    crypto_shred_log(target_id)