import cv2
import os
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce + tag + ciphertext

def decrypt_message(encrypted_message, key):
    nonce = encrypted_message[:16]
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode()

img = cv2.imread("scenery.jpg")

msg = input("Enter secret message: ")
password = input("Enter password: ")

key = get_random_bytes(16)  # Generate a random 128-bit key

encrypted_message = encrypt_message(msg, key)

# Embed encrypted message in the image
# Implement your steganography technique here...

cv2.imwrite("Encryptedmsg.jpg", img)

os.system("start Encryptedmsg.jpg")

pas = input("Enter passcode for Decryption: ")

if password == pas:
    # Retrieve the embedded message from the image
    # Implement your steganography technique here...

    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted message:", decrypted_message)
else:
    print("Not a valid key")