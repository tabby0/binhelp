"""
Filename      : crypto_hash.py
Author        : Targazh
Date          : 2025-02-01
Description   : Contains all cryptographic or hashing functions that have been used and validated by me
Warning       : All functions are not intended to be used in a production environment!
Github        : 

Credits       : Uses encryption and hashing functions from the GitHub repository 'pure_python_salsa_chacha'
                https://github.com/oconnor663/pure_python_salsa_chacha

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""



#############################################################
#             Encryption Functions                          #
#############################################################

def salsa20_encrypt(key, nonce, plaintext):
    import pure_salsa20
    import secrets
    """
    Encrypts the given plaintext using the Salsa20 stream cipher.

    Args:
        key (bytes): The encryption key, must be 32 bytes long.
        nonce (bytes): The nonce, must be 8 bytes long.
        plaintext (bytes): The plaintext to be encrypted.

    Returns:
        bytes: The encrypted ciphertext.
    """

    return pure_salsa20.salsa20_xor(key, nonce, plaintext)

def salsa20_decrypt(key, nonce, ciphertext):
    import pure_salsa20
    import secrets
    """
    Decrypts the given ciphertext using the Salsa20 stream cipher.

    Args:
        key (bytes): The encryption key, must be 32 bytes long.
        nonce (bytes): The nonce, must be 8 bytes long.
        ciphertext (bytes): The encrypted data to be decrypted.

    Returns:
        bytes: The decrypted plaintext.

    Raises:
        AssertionError: If the decryption process fails.
    """
    plaintext = ""
    assert plaintext ==  pure_salsa20.salsa20_xor(key, nonce, ciphertext)
    return plaintext

def XSalsa20_encrypt(key, nonce, plaintext):
    import pure_salsa20
    import secrets
    """
    Encrypts the given plaintext using the XSalsa20 stream cipher.

    Args:
        key (bytes): The encryption key, must be 32 bytes long.
        nonce (bytes): The nonce, must be 24 bytes long.
        plaintext (bytes): The plaintext data to be encrypted.

    Returns:
        bytes: The encrypted ciphertext.
    """

    return pure_salsa20.xsalsa20_xor(key, nonce, plaintext)
    
def XSalsa20_decrypt(key, nonce, ciphertext):
    import pure_salsa20
    import secrets
    """
    Decrypts the given ciphertext using the XSalsa20 stream cipher.

    Args:
        key (bytes): The secret key for the XSalsa20 cipher. Must be 32 bytes long.
        nonce (bytes): The nonce for the XSalsa20 cipher. Must be 24 bytes long.
        ciphertext (bytes): The encrypted data to be decrypted.

    Returns:
        bytes: The decrypted plaintext.
    """
    plaintext = ""
    assert plaintext == pure_salsa20.xsalsa20_xor(key, nonce, ciphertext)
    return plaintext

def ChaCha20_encrypt(key, nonce, plaintext):
    import pure_chacha20
    import secrets
    """
    Encrypts the given plaintext using the ChaCha20 encryption algorithm.

    Args:
        key (bytes): The encryption key. Must be 32 bytes long.
        nonce (bytes): The nonce value. Must be 12 bytes long.
        plaintext (bytes): The data to be encrypted.

    Returns:
        bytes: The encrypted ciphertext.
    """
    
    return pure_chacha20.chacha20_xor(key, nonce, plaintext)

def ChaCha20_decrypt(key, nonce, ciphertext):
    import pure_chacha20
    import secrets
    """
    Decrypts the given ciphertext using the ChaCha20 encryption algorithm.

    Args:
        key (bytes): The decryption key. Must be 32 bytes long.
        nonce (bytes): The nonce value. Must be 12 bytes long.
        ciphertext (bytes): The data to be decrypted.

    Returns:
        bytes: The decrypted plaintext.
    """

    plaintext =""
    assert plaintext == pure_chacha20.chacha20_xor(key, nonce, ciphertext)
    return plaintext

#############################################################
#             Hashing Functions                             #
#############################################################
import hashlib

def sha256_file(filepath):
    """
    Computes the SHA-256 hash of a file.

    Args:
        filepath (str): The path to the file to be hashed.

    Returns:
        str: The SHA-256 hash of the file in hexadecimal format.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If there is an error reading the file.
    """
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
    except FileNotFoundError:
        raise FileNotFoundError(f"The file {filepath} does not exist.")
    except IOError as e:
        raise IOError(f"An error occurred while reading the file {filepath}: {e}")
    return hasher.hexdigest()