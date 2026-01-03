import hvac
import sys

# 1. Connect to the local Vault server
# We use the token you generated
client = hvac.Client(
    url='http://127.0.0.1:8200',
    token='PASTE VAULT ROOT TOKEN HERE',
)

# Verify connection
if not client.is_authenticated():
    print(" Error: Valid authentication token required.")
    sys.exit(1)

print(" Connected to HashiCorp Vault successfully.")

# The name of the key we created in the previous step
KEY_NAME = "log-master-key"
PLAINTEXT_LOG = "User Admin logged in at 10:00 AM"

print(f"\n--- Step 1: Encrypting Log Data (Compliance) ---")
print(f"Original Log: {PLAINTEXT_LOG}")

# Ask Vault to encrypt the data
# Note: Vault expects base64, but hvac handles plaintext automatically in recent versions or requires encoding.
# We will send it as a simple string, hvac handles the API call.
encrypt_response = client.secrets.transit.encrypt_data(
    name=KEY_NAME,
    plaintext=PLAINTEXT_LOG.encode('utf-8').hex() # Vault expects base64 or hex usually, hex is safer here
)

ciphertext = encrypt_response['data']['ciphertext']
print(f" Ciphertext (Stored in IPFS): {ciphertext}")

print(f"\n--- Step 2: Decrypting Data (Authorized Access) ---")
# Authenticated user requests decryption
decrypt_response = client.secrets.transit.decrypt_data(
    name=KEY_NAME,
    ciphertext=ciphertext
)

decrypted_text = bytes.fromhex(decrypt_response['data']['plaintext']).decode('utf-8')
print(f" Decrypted Log: {decrypted_text}")

if decrypted_text == PLAINTEXT_LOG:
    print(" Integrity Check Passed: Data matches.")

# --- THE CRITICAL GDPR PART ---
print(f"\n--- Step 3: executing 'Right to be Forgotten' (Crypto-Shredding) ---")
print("  Deleting the encryption key from Vault...")

# Delete the key permanently
client.secrets.transit.delete_key(name=KEY_NAME)
print("  Key deleted.")

print(f"\n--- Step 4: Attempting Decryption after Deletion ---")
try:
    client.secrets.transit.decrypt_data(
        name=KEY_NAME,
        ciphertext=ciphertext
    )
except Exception as e:
    print(f" Success! Decryption failed as expected.")
    print(f"   Reason: {e}")
    print("   The data is now permanently inaccessible (GDPR Article 17 Compliant).")