import requests
import urllib3
urllib3.disable_warnings()

# === BURAYI DOLDUR ===
WAZUH_USER = "wazuh"
WAZUH_PASSWORD = "M1frDehOtqK2MnB++?VuSGug31GGj*Rm" 
# =====================

def test_connection():
    url = "https://localhost:55000/security/user/authenticate"
    auth = (WAZUH_USER, WAZUH_PASSWORD)
    
    print(f"📡 Deneniyor: {WAZUH_USER} / {WAZUH_PASSWORD}")
    
    try:
        # verify=False SSL hatasını yoksayar
        response = requests.post(url, auth=auth, verify=False)
        
        if response.status_code == 200:
            print("\n✅ BAŞARILI! Şifre doğru.")
            print(f"Token: {response.json()['data']['token'][:20]}...")
        else:
            print(f"\n❌ BAŞARISIZ! Hata Kodu: {response.status_code}")
            print(f"Detay: {response.text}")
            
    except Exception as e:
        print(f"\n❌ Bağlantı Hatası: {e}")

if __name__ == "__main__":
    test_connection()