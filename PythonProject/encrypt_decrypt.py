import sys
from tokenize import String

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

def encrypt_message(message):

    key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC)

    padded_message = pad(message.encode(), AES.block_size)

    encrypted_message = cipher.encrypt(padded_message)

    encrypted_message_with_iv = cipher.iv + encrypted_message

    return key, encrypted_message_with_iv

def decrypt_message(encrypted_message_with_iv, key):
    key = binascii.unhexlify(key)
    print(f"key = {binascii.hexlify(key).decode()}")
    encrypted_message_with_iv = binascii.unhexlify(encrypted_message_with_iv)


    iv = encrypted_message_with_iv[:AES.block_size]
    print(f"IV (byte): {iv}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")

    encrypted_message = encrypted_message_with_iv[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    # serve per togliere il padding
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    return decrypted_message.decode()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Encrypt: python encrypt_decrypt.py encrypt <message>")
        print("  Decrypt: python encrypt_decrypt.py decrypt <message_encrypted> <key>")
        sys.exit(1)

    operation = sys.argv[1]

    if operation == "encrypt":
        if len(sys.argv) != 3:
            print("Usage: python python_encrypt_decrypt.py flag_encrypt <message>")
            sys.exit(1)

        message = sys.argv[2]

        key, encrypted_message_with_iv = encrypt_message(message)

        # trasformazione in esadecimale per usare decode
        key_hex = binascii.hexlify(key).decode()
        encrypted_message_hex = binascii.hexlify(encrypted_message_with_iv).decode()

        print(f"Message encrypted: {encrypted_message_hex}")
        print(f"Key: {key_hex}")

    elif operation == "decrypt":
        if len(sys.argv) != 4:
            print("Usage: python python_encrypt_decrypt.py flag_decrypt <message_encrypted> <key>")
            sys.exit(1)

        encrypted_message_with_iv = sys.argv[2]
        key = sys.argv[3]

        try:
            decrypted_message = decrypt_message(encrypted_message_with_iv, key)
            print(f"Message decrypted: {decrypted_message}")
        except Exception as e:
            print(f"Decryption failed: {e}")

    else:
        print("Invalid flag. Use 'encrypt' to encrypt or 'decrypt' to decrypt.")
