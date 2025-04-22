from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

BS = AES.block_size

def pad(data):
    padding_length = BS - len(data) % BS
    return data + chr(padding_length) * padding_length

def unpad(data):
    padding_length = ord(data[-1])
    return data[:-padding_length]

def encrypt_AES_CBC(plain_text, key):
    key = key.ljust(16)[:16].encode()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plain_text)
    encrypted = cipher.encrypt(padded_text.encode())
    return base64.b64encode(iv + encrypted).decode()

def decrypt_AES_CBC(enc_text, key):
    try:
        key = key.ljust(16)[:16].encode()
        raw = base64.b64decode(enc_text)
        iv = raw[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(raw[16:]).decode()
        return unpad(decrypted)
    except Exception as e:
        return f"❌ Decryption failed: {str(e)}"

def menu():
    print("\n==== Secure Digital Transactions Menu ====")
    print("1. Encrypt Data")
    print("2. Decrypt Data")
    print("3. Exit")
    choice = input("Choose an option (1/2/3): ")
    return choice.strip()

if __name__ == "__main__":
    print("🔐 AES 128-bit CBC Mode Encryption Program")

    while True:
        choice = menu()

        if choice == '1':
            plain_text = input("Enter text to encrypt (transaction detail / credential): ")
            key = input("Enter secret key: ")
            encrypted = encrypt_AES_CBC(plain_text, key)
            print(f"✅ Encrypted Output: {encrypted}")

        elif choice == '2':
            encrypted_text = input("Enter Base64 encrypted text: ")
            key = input("Enter secret key used during encryption: ")
            decrypted = decrypt_AES_CBC(encrypted_text, key)
            print(f"✅ Decrypted Output: {decrypted}")

        elif choice == '3':
            print("👋 Exiting... Stay Secure!")
            break

        else:
            print("❗ Invalid choice. Please enter 1, 2, or 3.")