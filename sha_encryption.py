import hashlib
import itertools
import string

def encrypt_text(plaintext):
    """Encrypt the input text using SHA-256 and return the hex digest."""
    sha256_hash = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
    return sha256_hash

def brute_force_decrypt(hash_value):
    """Attempt to brute-force decrypt the SHA-256 hash by matching all combinations."""
    charset = string.ascii_letters + string.digits  # Alphanumeric only
    max_length = 4  # Limit to short strings due to computational constraints

    print("Attempting to brute-force decrypt...")
    for length in range(1, max_length + 1):
        print(f"Trying combinations of length {length}...")
        for attempt_tuple in itertools.product(charset, repeat=length):
            attempt = ''.join(attempt_tuple)
            sha256_attempt = hashlib.sha256(attempt.encode('utf-8')).hexdigest()

            if sha256_attempt == hash_value:
                print(f"Match found for {attempt} with hash {sha256_attempt}")
                return attempt  # Match found

    return None  # No match found

# Main Program
print("SHA-256 ENCRYPTION/DECRYPTION")
option = input("Enter Option: Encrypt/Decrypt (E/D): ").strip().upper()

if option == "E":
    # Encrypt option
    plaintext = input("Enter your text (up to 5 characters only): ").strip()
    if len(plaintext) > 5:
        print("Please enter text up to 5 characters only.")
    else:
        encrypted_text = encrypt_text(plaintext)
        print("Encrypted Text SHA-256:", encrypted_text)

elif option == "D":
    # Decrypt option
    hash_value = input("Enter SHA-256 hash to decrypt: ").strip()
    result = brute_force_decrypt(hash_value)
    if result:
        print("Found matching input:", result)
    else:
        print("No matching input found for the given hash.")

else:
    print("Invalid option. Please enter 'E' for encryption or 'D' for decryption.")
