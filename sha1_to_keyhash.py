import base64
import sys

def sha1_to_keyhash(sha1_hex):
    """
    Convert a SHA-1 hexadecimal string to a Base64-encoded Key Hash.

    :param sha1_hex: SHA-1 hexadecimal string with or without colons.
    :return: Base64-encoded Key Hash string.
    """
    # Remove all colons, spaces, and newline characters
    sha1_clean = sha1_hex.replace(':', '').replace(' ', '').strip()
    
    # Validate the length of the SHA-1 fingerprint (40 hexadecimal characters)
    if len(sha1_clean) != 40:
        raise ValueError("Invalid SHA-1 fingerprint length. Expected 40 hexadecimal characters.")
    
    try:
        # Convert the hexadecimal string to a byte array
        sha1_bytes = bytes.fromhex(sha1_clean)
    except ValueError as e:
        raise ValueError("Invalid SHA-1 hexadecimal string.") from e
    
    # Encode the byte array to a Base64 string
    key_hash = base64.b64encode(sha1_bytes).decode('utf-8')
    
    return key_hash

def main():
    """
    Main function to handle command-line input or interactive input and output the Key Hash.
    """
    if len(sys.argv) == 2:
        sha1_input = sys.argv[1]
    else:
        sha1_input = input("Please enter your SHA-1 fingerprint (with or without colons): ")
    
    try:
        key_hash = sha1_to_keyhash(sha1_input)
        print(f"Key Hash: {key_hash}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
