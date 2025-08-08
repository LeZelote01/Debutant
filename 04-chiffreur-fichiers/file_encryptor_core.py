#!/usr/bin/env python3
"""
Version simplifiée du chiffreur de fichiers pour démonstration CLI.
"""

import os
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

class FileEncryptor:
    def __init__(self):
        self.operations_log = []
    
    def generate_key_from_password(self, password, salt=None):
        """Génère une clé Fernet à partir d'un mot de passe."""
        if salt is None:
            salt = os.urandom(16)
        
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key, salt
    
    def encrypt_file(self, input_path, output_path, password):
        """Chiffre un fichier."""
        try:
            if not os.path.isfile(input_path):
                return {'success': False, 'error': 'Fichier source introuvable'}
            
            # Générer la clé et le sel
            key, salt = self.generate_key_from_password(password)
            fernet = Fernet(key)
            
            # Obtenir la taille du fichier
            file_size = os.path.getsize(input_path)
            
            # Chiffrer le fichier
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Écrire signature
                outfile.write(b'FENC\x01')
                
                # Écrire le sel
                outfile.write(len(salt).to_bytes(2, 'big'))
                outfile.write(salt)
                
                # Nom du fichier original
                original_name = os.path.basename(input_path).encode('utf-8')
                outfile.write(len(original_name).to_bytes(2, 'big'))
                outfile.write(original_name)
                
                # Timestamp
                timestamp = datetime.now().isoformat().encode('utf-8')
                outfile.write(len(timestamp).to_bytes(2, 'big'))
                outfile.write(timestamp)
                
                # Taille originale
                outfile.write(file_size.to_bytes(8, 'big'))
                
                # Chiffrer le contenu
                while chunk := infile.read(8192):
                    encrypted_chunk = fernet.encrypt(chunk)
                    outfile.write(len(encrypted_chunk).to_bytes(4, 'big'))
                    outfile.write(encrypted_chunk)
            
            return {
                'success': True,
                'output_file': output_path,
                'original_size': file_size,
                'encrypted_size': os.path.getsize(output_path)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_file(self, input_path, output_path, password):
        """Déchiffre un fichier."""
        try:
            if not os.path.isfile(input_path):
                return {'success': False, 'error': 'Fichier chiffré introuvable'}
            
            with open(input_path, 'rb') as infile:
                # Vérifier signature
                signature = infile.read(5)
                if signature != b'FENC\x01':
                    return {'success': False, 'error': 'Fichier non reconnu'}
                
                # Lire le sel
                salt_length = int.from_bytes(infile.read(2), 'big')
                salt = infile.read(salt_length)
                
                # Générer la clé
                key, _ = self.generate_key_from_password(password, salt)
                fernet = Fernet(key)
                
                # Lire métadonnées
                name_length = int.from_bytes(infile.read(2), 'big')
                original_name = infile.read(name_length).decode('utf-8')
                
                timestamp_length = int.from_bytes(infile.read(2), 'big')
                timestamp = infile.read(timestamp_length).decode('utf-8')
                
                original_size = int.from_bytes(infile.read(8), 'big')
                
                # Déchiffrer le contenu
                with open(output_path, 'wb') as outfile:
                    while True:
                        try:
                            chunk_size_bytes = infile.read(4)
                            if len(chunk_size_bytes) < 4:
                                break
                            
                            chunk_size = int.from_bytes(chunk_size_bytes, 'big')
                            encrypted_chunk = infile.read(chunk_size)
                            
                            if len(encrypted_chunk) < chunk_size:
                                break
                            
                            decrypted_chunk = fernet.decrypt(encrypted_chunk)
                            outfile.write(decrypted_chunk)
                        
                        except Exception as e:
                            return {'success': False, 'error': f'Mot de passe incorrect: {str(e)}'}
            
            return {
                'success': True,
                'output_file': output_path,
                'original_name': original_name,
                'original_size': original_size,
                'encryption_timestamp': timestamp
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}