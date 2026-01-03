import hvac
import sys

# ==========================================
# SETTINGS
# ==========================================
VAULT_URL = "http://127.0.0.1:8200"
VAULT_TOKEN = "PASTE VAULT ROOT TOKEN HERE" # Don't forget to update if the token has changed
# We removed the KEY_NAME constant because it is now determined dynamically.
# ==========================================

def delete_key():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    
    if not client.is_authenticated():
        print(" Vault Authentication Failed.")
        sys.exit(1)

    print("\n  GDPR RIGHT TO BE FORGOTTEN TOOL (SURGICAL DELETION)")
    print("-" * 60)

    # STEP 1: Ask User for Log ID to be Deleted
    target_log_id = input(" Enter the Log ID to be deleted. (Ex: log-1767...): ").strip()
    
    if not target_log_id:
        print(" Error: Log ID cannot be empty.")
        sys.exit(1)

    # Derive key name from naming logic in agent.py
    unique_key_name = f"key-{target_log_id}"

    print(f"\n  WARNING: The encryption key named '{unique_key_name}' will be DELETED from the Vault.")
    print(f"    This process only renders the log with ID '{target_log_id}' unreadable.")
    print("    Other logs are unaffected.")
    
    confirm = input("\nThis action is irreversible. Are you sure? (yes/no): ")
    if confirm.lower() != "yes":
        print("The transaction has been cancelled.")
        sys.exit(0)

    try:
        # STEP 2: First we turn on the deletion permission (Deletion Allowed)
        print(f" 🔓 Deletion permission is being granted for'{unique_key_name}' ...")
        client.secrets.transit.update_key_configuration(
            name=unique_key_name,
            deletion_allowed=True
        )

        # STEP 3: Now we delete that log private key
        client.secrets.transit.delete_key(name=unique_key_name)
        
        print(f"\n SUCCESSFUL: '{unique_key_name}' has been permanently destroyed.")
        print("    The relevant log data can no longer be recovered mathematically..")
        print("    (GDPR Article 17 Requirement Met)")
        
    except hvac.exceptions.InvalidPath:
        print(f"\n Error: A key named '{unique_key_name}' could not be found in Vault.")
        print("    Make sure you have entered the Log ID correctly.")
    except Exception as e:
        print(f"\n Unexpected Error: {e}")

if __name__ == "__main__":
    delete_key()