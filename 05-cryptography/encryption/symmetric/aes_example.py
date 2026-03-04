#!/usr/bin/env python3

import os
import base64
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import getpass

class RSAEncryption:
    """
    RSA Encryption/Decryption with digital signatures
    """
    
    def __init__(self, key_size=2048):
        """
        Initialize RSA with new key pair
        
        Args:
            key_size: RSA key size (2048, 3072, or 4096 bits)
        """
        self.backend = default_backend()
        self.key_size = key_size
        
        print(f"[*] Generating {key_size}-bit RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        print(f"[✓] Key pair generated")
    
    def load_private_key(self, filename, password=None):
        """Load private key from PEM file"""
        with open(filename, 'rb') as f:
            key_data = f.read()
        
        if password:
            password = password.encode()
        
        self.private_key = serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        print(f"[✓] Loaded private key from {filename}")
    
    def load_public_key(self, filename):
        """Load public key from PEM file"""
        with open(filename, 'rb') as f:
            key_data = f.read()
        
        self.public_key = serialization.load_pem_public_key(
            key_data,
            backend=self.backend
        )
        print(f"[✓] Loaded public key from {filename}")
    
    def save_private_key(self, filename, password=None):
        """Save private key to PEM file"""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"[✓] Private key saved to {filename}")
    
    def save_public_key(self, filename):
        """Save public key to PEM file"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"[✓] Public key saved to {filename}")
    
    def encrypt(self, plaintext):
        """
        Encrypt data with public key
        
        Note: RSA can only encrypt limited data based on key size.
        For larger data, use hybrid encryption (RSA + AES).
        """
        max_length = self.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
        if len(plaintext) > max_length:
            raise ValueError(f"Data too long for RSA encryption. Max: {max_length} bytes")
        
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt data with private key"""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def sign(self, message):
        """Sign a message with private key"""
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify(self, message, signature):
        """Verify a signature with public key"""
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def encrypt_file(self, input_file, output_file):
        """
        Hybrid encryption: RSA + AES
        For large files, we use AES for the data and RSA for the AES key
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        print(f"[*] Encrypting {input_file} using hybrid encryption (RSA + AES)")
        
        # Generate random AES key and IV
        aes_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)
        
        # Read input file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Encrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        from cryptography.hazmat.primitives import padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_key = self.encrypt(aes_key)
        
        # Write output: encrypted_key_length(4) + encrypted_key + iv + ciphertext
        with open(output_file, 'wb') as f:
            f.write(len(encrypted_key).to_bytes(4, 'big'))
            f.write(encrypted_key)
            f.write(iv)
            f.write(ciphertext)
        
        print(f"[✓] Encryption complete")
        return True
    
    def decrypt_file(self, input_file, output_file):
        """Hybrid decryption: RSA + AES"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        
        print(f"[*] Decrypting {input_file}...")
        
        with open(input_file, 'rb') as f:
            # Read encrypted key length
            key_len = int.from_bytes(f.read(4), 'big')
            
            # Read encrypted key
            encrypted_key = f.read(key_len)
            
            # Read IV
            iv = f.read(16)
            
            # Read ciphertext
            ciphertext = f.read()
        
        # Decrypt AES key with RSA
        aes_key = self.decrypt(encrypted_key)
        
        # Decrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"[✓] Decryption complete")
        return True

def demonstrate_rsa():
    """Demonstrate RSA encryption and signatures"""
    print("""
    ╔═══════════════════════════════════════╗
    ║         RSA Encryption Demo           ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Create RSA instance
    rsa_crypto = RSAEncryption(2048)
    
    # 1. Basic Encryption/Decryption
    print("\n" + "="*50)
    print("1. Basic Encryption/Decryption")
    print("="*50)
    
    message = b"Secret message for RSA!"
    print(f"   Original: {message.decode()}")
    
    ciphertext = rsa_crypto.encrypt(message)
    print(f"   Encrypted (b64): {base64.b64encode(ciphertext).decode()[:50]}...")
    
    decrypted = rsa_crypto.decrypt(ciphertext)
    print(f"   Decrypted: {decrypted.decode()}")
    
    # 2. Digital Signatures
    print("\n" + "="*50)
    print("2. Digital Signatures")
    print("="*50)
    
    document = b"Important contract: Pay $1000"
    signature = rsa_crypto.sign(document)
    print(f"   Document: {document.decode()}")
    print(f"   Signature (b64): {base64.b64encode(signature).decode()[:50]}...")
    
    # Verify with correct document
    valid = rsa_crypto.verify(document, signature)
    print(f"   Signature valid: {valid}")
    
    # Try with tampered document
    tampered = b"Important contract: Pay $10000"
    valid = rsa_crypto.verify(tampered, signature)
    print(f"   Signature with tampered document: {valid}")
    
    # 3. Key Export/Import
    print("\n" + "="*50)
    print("3. Key Export/Import")
    print("="*50)
    
    # Save keys
    rsa_crypto.save_private_key("private.pem", "password123")
    rsa_crypto.save_public_key("public.pem")
    
    # Load keys in new instance
    rsa2 = RSAEncryption()
    rsa2.load_public_key("public.pem")
    
    # Encrypt with loaded public key
    message2 = b"Message for exported key"
    ciphertext2 = rsa2.encrypt(message2)
    print(f"   Encrypted with loaded public key")
    
    # Load private key for decryption
    rsa2.load_private_key("private.pem", "password123")
    decrypted2 = rsa2.decrypt(ciphertext2)
    print(f"   Decrypted with loaded private key: {decrypted2.decode()}")
    
    # Cleanup
    os.remove("private.pem")
    os.remove("public.pem")

def main():
    parser = argparse.ArgumentParser(description='RSA Encryption Tool')
    parser.add_argument('--gen-keys', nargs=2, metavar=('PRIV', 'PUB'),
                       help='Generate key pair (private.pem public.pem)')
    parser.add_argument('--encrypt', help='Encrypt a file')
    parser.add_argument('--decrypt', help='Decrypt a file')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--public-key', help='Public key file for encryption')
    parser.add_argument('--private-key', help='Private key file for decryption')
    parser.add_argument('--password', help='Password for private key')
    parser.add_argument('--sign', help='Sign a file')
    parser.add_argument('--verify', nargs=2, metavar=('FILE', 'SIG'),
                       help='Verify file signature')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    
    args = parser.parse_args()
    
    if args.demo:
        demonstrate_rsa()
        return
    
    rsa_crypto = RSAEncryption()
    
    if args.gen_keys:
        priv_file, pub_file = args.gen_keys
        password = args.password or getpass.getpass("Enter password for private key: ")
        rsa_crypto.save_private_key(priv_file, password)
        rsa_crypto.save_public_key(pub_file)
        print(f"[✓] Key pair generated: {priv_file}, {pub_file}")
    
    elif args.encrypt and args.output:
        if not args.public_key:
            print("[!] Need public key for encryption")
            return
        rsa_crypto.load_public_key(args.public_key)
        rsa_crypto.encrypt_file(args.encrypt, args.output)
    
    elif args.decrypt and args.output:
        if not args.private_key:
            print("[!] Need private key for decryption")
            return
        password = args.password or getpass.getpass("Enter password for private key: ")
        rsa_crypto.load_private_key(args.private_key, password)
        rsa_crypto.decrypt_file(args.decrypt, args.output)
    
    elif args.sign:
        if not args.private_key:
            print("[!] Need private key for signing")
            return
        password = args.password or getpass.getpass("Enter password for private key: ")
        rsa_crypto.load_private_key(args.private_key, password)
        
        with open(args.sign, 'rb') as f:
            data = f.read()
        signature = rsa_crypto.sign(data)
        
        sig_file = args.sign + ".sig"
        with open(sig_file, 'wb') as f:
            f.write(signature)
        print(f"[✓] Signature saved to {sig_file}")
    
    elif args.verify:
        file_path, sig_path = args.verify
        if not args.public_key:
            print("[!] Need public key for verification")
            return
        rsa_crypto.load_public_key(args.public_key)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        with open(sig_path, 'rb') as f:
            signature = f.read()
        
        valid = rsa_crypto.verify(data, signature)
        if valid:
            print(f"[✓] Signature is valid")
        else:
            print(f"[✗] Signature is invalid")

if __name__ == "__main__":
    main()
