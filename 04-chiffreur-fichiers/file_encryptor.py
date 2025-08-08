#!/usr/bin/env python3
"""
Chiffreur de Fichiers Personnel
==============================

Application desktop avec interface graphique pour chiffrer et déchiffrer
des fichiers personnels en utilisant le chiffrement AES-256 via Fernet.

Auteur: Jean Yves (LeZelote)
Date: Mai 2025
Version: 1.0
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import json
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import zipfile
import shutil

class FileEncryptor:
    """Classe principale pour le chiffrement/déchiffrement de fichiers."""
    
    def __init__(self):
        self.operations_log = []
        self.log_file = "encryption_operations.json"
        self.load_operations_log()
    
    def generate_key_from_password(self, password, salt=None):
        """
        Génère une clé Fernet à partir d'un mot de passe.
        
        Args:
            password (str): Mot de passe utilisateur
            salt (bytes): Sel pour la dérivation (généré si None)
        
        Returns:
            tuple: (clé_fernet, sel)
        """
        if salt is None:
            salt = os.urandom(16)  # 128 bits de sel
        
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,  # OWASP recommande 100k+ itérations
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key, salt
    
    def encrypt_file(self, input_path, output_path, password, progress_callback=None):
        """
        Chiffre un fichier avec AES-256.
        
        Args:
            input_path (str): Chemin du fichier source
            output_path (str): Chemin du fichier chiffré
            password (str): Mot de passe de chiffrement
            progress_callback (function): Callback pour le progrès
        
        Returns:
            dict: Résultat de l'opération
        """
        try:
            # Vérifier que le fichier existe
            if not os.path.isfile(input_path):
                return {'success': False, 'error': 'Fichier source introuvable'}
            
            # Générer la clé et le sel
            key, salt = self.generate_key_from_password(password)
            fernet = Fernet(key)
            
            # Obtenir la taille du fichier pour le progrès
            file_size = os.path.getsize(input_path)
            
            if progress_callback:
                progress_callback(0, f"Début du chiffrement de {os.path.basename(input_path)}")
            
            # Créer le fichier de sortie avec métadonnées
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Écrire la signature et les métadonnées
                signature = b'FENC'  # File Encryption signature
                version = b'\x01\x00\x00'  # Version 1.0 (2 bytes)
                outfile.write(signature + version)
                
                # Écrire le sel
                outfile.write(len(salt).to_bytes(2, 'big'))
                outfile.write(salt)
                
                # Métadonnées du fichier original
                original_name = os.path.basename(input_path).encode('utf-8')
                outfile.write(len(original_name).to_bytes(2, 'big'))
                outfile.write(original_name)
                
                # Timestamp de chiffrement
                timestamp = datetime.now().isoformat().encode('utf-8')
                outfile.write(len(timestamp).to_bytes(2, 'big'))
                outfile.write(timestamp)
                
                # Taille du fichier original
                outfile.write(file_size.to_bytes(8, 'big'))
                
                # Chiffrer le contenu par blocs
                bytes_processed = 0
                chunk_size = 8192  # 8KB chunks
                
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk = fernet.encrypt(chunk)
                    
                    # Écrire la taille du chunk chiffré puis le chunk
                    outfile.write(len(encrypted_chunk).to_bytes(4, 'big'))
                    outfile.write(encrypted_chunk)
                    
                    bytes_processed += len(chunk)
                    
                    if progress_callback:
                        progress = int((bytes_processed / file_size) * 100)
                        progress_callback(progress, f"Chiffrement... {progress}%")
            
            # Enregistrer l'opération
            operation = {
                'type': 'encrypt',
                'input_file': input_path,
                'output_file': output_path,
                'timestamp': datetime.now().isoformat(),
                'file_size': file_size,
                'success': True
            }
            self.operations_log.append(operation)
            self.save_operations_log()
            
            if progress_callback:
                progress_callback(100, f"Chiffrement terminé: {os.path.basename(output_path)}")
            
            return {
                'success': True,
                'output_file': output_path,
                'original_size': file_size,
                'encrypted_size': os.path.getsize(output_path)
            }
            
        except Exception as e:
            error_msg = f"Erreur de chiffrement: {str(e)}"
            if progress_callback:
                progress_callback(0, error_msg)
            return {'success': False, 'error': error_msg}
    
    def decrypt_file(self, input_path, output_path, password, progress_callback=None):
        """
        Déchiffre un fichier AES-256.
        
        Args:
            input_path (str): Chemin du fichier chiffré
            output_path (str): Chemin du fichier déchiffré
            password (str): Mot de passe de déchiffrement
            progress_callback (function): Callback pour le progrès
        
        Returns:
            dict: Résultat de l'opération
        """
        try:
            if not os.path.isfile(input_path):
                return {'success': False, 'error': 'Fichier chiffré introuvable'}
            
            encrypted_size = os.path.getsize(input_path)
            
            if progress_callback:
                progress_callback(0, f"Début du déchiffrement de {os.path.basename(input_path)}")
            
            with open(input_path, 'rb') as infile:
                # Vérifier la signature
                signature = infile.read(4)
                if signature != b'FENC':
                    return {'success': False, 'error': 'Fichier non reconnu ou corrompu'}
                
                # Lire la version
                version = infile.read(2)
                if version != b'\x01\x00':
                    return {'success': False, 'error': 'Version de fichier non supportée'}
                
                # Lire le sel
                salt_length = int.from_bytes(infile.read(2), 'big')
                salt = infile.read(salt_length)
                
                # Générer la clé avec le sel
                key, _ = self.generate_key_from_password(password, salt)
                fernet = Fernet(key)
                
                # Lire les métadonnées
                name_length = int.from_bytes(infile.read(2), 'big')
                original_name = infile.read(name_length).decode('utf-8')
                
                timestamp_length = int.from_bytes(infile.read(2), 'big')
                timestamp = infile.read(timestamp_length).decode('utf-8')
                
                original_size = int.from_bytes(infile.read(8), 'big')
                
                # Déchiffrer le contenu
                with open(output_path, 'wb') as outfile:
                    bytes_processed = 0
                    
                    while True:
                        try:
                            # Lire la taille du chunk chiffré
                            chunk_size_bytes = infile.read(4)
                            if len(chunk_size_bytes) < 4:
                                break
                            
                            chunk_size = int.from_bytes(chunk_size_bytes, 'big')
                            encrypted_chunk = infile.read(chunk_size)
                            
                            if len(encrypted_chunk) < chunk_size:
                                break
                            
                            # Déchiffrer le chunk
                            decrypted_chunk = fernet.decrypt(encrypted_chunk)
                            outfile.write(decrypted_chunk)
                            
                            bytes_processed += len(decrypted_chunk)
                            
                            if progress_callback and original_size > 0:
                                progress = int((bytes_processed / original_size) * 100)
                                progress_callback(progress, f"Déchiffrement... {progress}%")
                        
                        except Exception as e:
                            return {'success': False, 'error': f'Mot de passe incorrect ou fichier corrompu: {str(e)}'}
            
            # Enregistrer l'opération
            operation = {
                'type': 'decrypt',
                'input_file': input_path,
                'output_file': output_path,
                'timestamp': datetime.now().isoformat(),
                'file_size': original_size,
                'success': True,
                'original_name': original_name,
                'encryption_timestamp': timestamp
            }
            self.operations_log.append(operation)
            self.save_operations_log()
            
            if progress_callback:
                progress_callback(100, f"Déchiffrement terminé: {os.path.basename(output_path)}")
            
            return {
                'success': True,
                'output_file': output_path,
                'original_name': original_name,
                'original_size': original_size,
                'encryption_timestamp': timestamp
            }
            
        except Exception as e:
            error_msg = f"Erreur de déchiffrement: {str(e)}"
            if progress_callback:
                progress_callback(0, error_msg)
            return {'success': False, 'error': error_msg}
    
    def encrypt_directory(self, input_dir, output_file, password, progress_callback=None):
        """
        Chiffre un répertoire entier en créant une archive chiffrée.
        
        Args:
            input_dir (str): Répertoire à chiffrer
            output_file (str): Fichier de sortie (.fenc)
            password (str): Mot de passe
            progress_callback (function): Callback pour le progrès
        
        Returns:
            dict: Résultat de l'opération
        """
        try:
            if not os.path.isdir(input_dir):
                return {'success': False, 'error': 'Répertoire source introuvable'}
            
            if progress_callback:
                progress_callback(0, "Création de l'archive du répertoire...")
            
            # Créer une archive temporaire
            temp_zip = output_file + '.tmp.zip'
            
            # Compter le nombre total de fichiers pour le progrès
            total_files = sum([len(files) for r, d, files in os.walk(input_dir)])
            processed_files = 0
            
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(input_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        archive_path = os.path.relpath(file_path, input_dir)
                        zipf.write(file_path, archive_path)
                        
                        processed_files += 1
                        if progress_callback:
                            progress = int((processed_files / total_files) * 50)  # 50% pour l'archive
                            progress_callback(progress, f"Archivage... {processed_files}/{total_files}")
            
            if progress_callback:
                progress_callback(50, "Archive créée, début du chiffrement...")
            
            # Chiffrer l'archive
            result = self.encrypt_file(temp_zip, output_file, password, 
                                     lambda p, msg: progress_callback(50 + p//2, msg) if progress_callback else None)
            
            # Supprimer l'archive temporaire
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
            
            if result['success']:
                result['directory_encrypted'] = True
                result['total_files'] = total_files
            
            return result
            
        except Exception as e:
            # Nettoyer en cas d'erreur
            temp_zip = output_file + '.tmp.zip'
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
            
            error_msg = f"Erreur de chiffrement du répertoire: {str(e)}"
            if progress_callback:
                progress_callback(0, error_msg)
            return {'success': False, 'error': error_msg}
    
    def batch_encrypt(self, file_list, output_dir, password, progress_callback=None):
        """
        Chiffre plusieurs fichiers en lot.
        
        Args:
            file_list (list): Liste des fichiers à chiffrer
            output_dir (str): Répertoire de sortie
            password (str): Mot de passe
            progress_callback (function): Callback pour le progrès
        
        Returns:
            dict: Résultats de toutes les opérations
        """
        results = {
            'success_count': 0,
            'error_count': 0,
            'operations': [],
            'total_files': len(file_list)
        }
        
        for i, file_path in enumerate(file_list):
            if progress_callback:
                progress_callback(
                    int((i / len(file_list)) * 100),
                    f"Traitement {i+1}/{len(file_list)}: {os.path.basename(file_path)}"
                )
            
            # Déterminer le nom de sortie
            base_name = os.path.basename(file_path)
            output_path = os.path.join(output_dir, base_name + '.fenc')
            
            # Éviter les écrasements
            counter = 1
            while os.path.exists(output_path):
                name, ext = os.path.splitext(base_name)
                output_path = os.path.join(output_dir, f"{name}_{counter}{ext}.fenc")
                counter += 1
            
            # Chiffrer le fichier
            result = self.encrypt_file(file_path, output_path, password)
            result['source_file'] = file_path
            results['operations'].append(result)
            
            if result['success']:
                results['success_count'] += 1
            else:
                results['error_count'] += 1
        
        if progress_callback:
            progress_callback(100, f"Batch terminé: {results['success_count']} succès, {results['error_count']} erreurs")
        
        return results
    
    def load_operations_log(self):
        """Charge l'historique des opérations."""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    self.operations_log = json.load(f)
            except:
                self.operations_log = []
        else:
            self.operations_log = []
    
    def save_operations_log(self):
        """Sauvegarde l'historique des opérations."""
        try:
            # Limiter l'historique à 1000 entrées
            if len(self.operations_log) > 1000:
                self.operations_log = self.operations_log[-1000:]
            
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(self.operations_log, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Erreur sauvegarde historique: {e}")
    
    def get_file_info(self, file_path):
        """
        Obtient les informations d'un fichier chiffré.
        
        Args:
            file_path (str): Chemin du fichier chiffré
        
        Returns:
            dict: Informations du fichier
        """
        try:
            if not os.path.isfile(file_path):
                return None
            
            with open(file_path, 'rb') as f:
                # Vérifier la signature
                signature = f.read(4)
                if signature != b'FENC':
                    return None
                
                version = f.read(2)
                if version != b'\x01\x00':
                    return None
                
                # Lire les métadonnées
                salt_length = int.from_bytes(f.read(2), 'big')
                f.read(salt_length)  # Ignorer le sel
                
                name_length = int.from_bytes(f.read(2), 'big')
                original_name = f.read(name_length).decode('utf-8')
                
                timestamp_length = int.from_bytes(f.read(2), 'big')
                timestamp = f.read(timestamp_length).decode('utf-8')
                
                original_size = int.from_bytes(f.read(8), 'big')
                
                return {
                    'original_name': original_name,
                    'encryption_timestamp': timestamp,
                    'original_size': original_size,
                    'encrypted_size': os.path.getsize(file_path),
                    'is_encrypted': True
                }
        
        except Exception as e:
            return None


class FileEncryptorGUI:
    """Interface graphique pour le chiffreur de fichiers."""
    
    def __init__(self):
        self.encryptor = FileEncryptor()
        self.setup_gui()
        
    def setup_gui(self):
        """Configure l'interface graphique."""
        self.root = tk.Tk()
        self.root.title("🔒 Chiffreur de Fichiers Personnel v1.0")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Configuration du style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Variables
        self.selected_files = []
        self.operation_mode = tk.StringVar(value='encrypt')
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        
        self.create_widgets()
        
    def create_widgets(self):
        """Crée tous les widgets de l'interface."""
        # Frame principal avec onglets
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Onglet Chiffrement/Déchiffrement
        self.main_frame = ttk.Frame(notebook)
        notebook.add(self.main_frame, text='🔐 Chiffrement/Déchiffrement')
        
        # Onglet Historique
        self.history_frame = ttk.Frame(notebook)
        notebook.add(self.history_frame, text='📊 Historique')
        
        # Onglet À propos
        self.about_frame = ttk.Frame(notebook)
        notebook.add(self.about_frame, text='ℹ️ À propos')
        
        self.create_main_tab()
        self.create_history_tab()
        self.create_about_tab()
        
    def create_main_tab(self):
        """Crée l'onglet principal de chiffrement."""
        # Mode de fonctionnement
        mode_frame = ttk.LabelFrame(self.main_frame, text="Mode d'opération", padding=10)
        mode_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Radiobutton(mode_frame, text="🔒 Chiffrer des fichiers", 
                       variable=self.operation_mode, value='encrypt').pack(side='left', padx=20)
        ttk.Radiobutton(mode_frame, text="🔓 Déchiffrer des fichiers", 
                       variable=self.operation_mode, value='decrypt').pack(side='left', padx=20)
        
        # Sélection de fichiers
        files_frame = ttk.LabelFrame(self.main_frame, text="Sélection de fichiers", padding=10)
        files_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Boutons de sélection
        buttons_frame = ttk.Frame(files_frame)
        buttons_frame.pack(fill='x', pady=5)
        
        ttk.Button(buttons_frame, text="📁 Ajouter des fichiers", 
                  command=self.add_files).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="📂 Ajouter un dossier", 
                  command=self.add_directory).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="🗑️ Effacer la liste", 
                  command=self.clear_files).pack(side='left', padx=5)
        
        # Liste des fichiers sélectionnés
        self.files_listbox = tk.Listbox(files_frame, height=8)
        scrollbar = ttk.Scrollbar(files_frame, orient='vertical', command=self.files_listbox.yview)
        self.files_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.files_listbox.pack(side='left', fill='both', expand=True, pady=5)
        scrollbar.pack(side='right', fill='y', pady=5)
        
        # Configuration de mot de passe
        password_frame = ttk.LabelFrame(self.main_frame, text="Configuration du mot de passe", padding=10)
        password_frame.pack(fill='x', padx=10, pady=5)
        
        # Mot de passe
        ttk.Label(password_frame, text="Mot de passe:").grid(row=0, column=0, sticky='w', pady=2)
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, 
                                       show='*', width=30)
        self.password_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=2)
        
        # Confirmation (pour chiffrement seulement)
        ttk.Label(password_frame, text="Confirmer:").grid(row=1, column=0, sticky='w', pady=2)
        self.confirm_entry = ttk.Entry(password_frame, textvariable=self.confirm_password_var, 
                                      show='*', width=30)
        self.confirm_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=2)
        
        # Bouton d'affichage du mot de passe
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = ttk.Checkbutton(password_frame, text="Afficher", 
                                                  variable=self.show_password_var,
                                                  command=self.toggle_password_visibility)
        self.show_password_check.grid(row=0, column=2, padx=5)
        
        password_frame.columnconfigure(1, weight=1)
        
        # Bouton d'action principal
        action_frame = ttk.Frame(self.main_frame)
        action_frame.pack(fill='x', padx=10, pady=10)
        
        self.action_button = ttk.Button(action_frame, text="🚀 Démarrer l'opération", 
                                       command=self.start_operation, style='Accent.TButton')
        self.action_button.pack()
        
        # Barre de progression et statut
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.main_frame, variable=self.progress_var, 
                                           maximum=100, length=400)
        self.progress_bar.pack(padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Prêt")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
        self.status_label.pack(pady=5)
        
    def create_history_tab(self):
        """Crée l'onglet d'historique des opérations."""
        # Frame pour les boutons
        buttons_frame = ttk.Frame(self.history_frame)
        buttons_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="🔄 Actualiser", 
                  command=self.refresh_history).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="📄 Exporter", 
                  command=self.export_history).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="🗑️ Effacer l'historique", 
                  command=self.clear_history).pack(side='left', padx=5)
        
        # Zone de texte pour l'historique
        self.history_text = scrolledtext.ScrolledText(self.history_frame, height=20)
        self.history_text.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.refresh_history()
    
    def create_about_tab(self):
        """Crée l'onglet à propos."""
        about_text = """
🔒 Chiffreur de Fichiers Personnel v1.0

Outil de chiffrement sécurisé pour vos fichiers personnels.

Fonctionnalités:
• Chiffrement AES-256 via cryptographie Fernet
• Dérivation de clé PBKDF2 avec 100k itérations  
• Support des fichiers individuels et dossiers
• Traitement par lot (batch processing)
• Historique détaillé des opérations
• Interface graphique intuitive

Sécurité:
• Chiffrement authentifié AES-256-GCM
• Sel aléatoire unique par fichier
• Métadonnées intégrées (nom, timestamp)
• Vérification d'intégrité automatique

Auteur: Assistant IA
Date: Juillet 2025
Licence: MIT

⚠️ Important:
• Gardez vos mots de passe en sécurité
• Sauvegardez vos fichiers chiffrés
• La perte du mot de passe rend les données irrécupérables
        """
        
        text_widget = scrolledtext.ScrolledText(self.about_frame, wrap='word')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', about_text)
        text_widget.configure(state='disabled')
    
    def add_files(self):
        """Ajoute des fichiers à la liste de sélection."""
        if self.operation_mode.get() == 'encrypt':
            filetypes = [("Tous les fichiers", "*.*")]
        else:
            filetypes = [("Fichiers chiffrés", "*.fenc"), ("Tous les fichiers", "*.*")]
        
        files = filedialog.askopenfilenames(
            title="Sélectionner des fichiers",
            filetypes=filetypes
        )
        
        for file_path in files:
            if file_path not in self.selected_files:
                self.selected_files.append(file_path)
                self.files_listbox.insert(tk.END, os.path.basename(file_path))
    
    def add_directory(self):
        """Ajoute un dossier à traiter."""
        directory = filedialog.askdirectory(title="Sélectionner un dossier")
        
        if directory:
            if self.operation_mode.get() == 'encrypt':
                # Pour chiffrement, ajouter le dossier lui-même
                if directory not in self.selected_files:
                    self.selected_files.append(directory)
                    self.files_listbox.insert(tk.END, f"📁 {os.path.basename(directory)}/")
            else:
                # Pour déchiffrement, ajouter tous les fichiers .fenc
                fenc_files = []
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.endswith('.fenc'):
                            fenc_files.append(os.path.join(root, file))
                
                for file_path in fenc_files:
                    if file_path not in self.selected_files:
                        self.selected_files.append(file_path)
                        self.files_listbox.insert(tk.END, os.path.basename(file_path))
                
                messagebox.showinfo("Dossier ajouté", f"{len(fenc_files)} fichiers .fenc trouvés")
    
    def clear_files(self):
        """Efface la liste des fichiers sélectionnés."""
        self.selected_files.clear()
        self.files_listbox.delete(0, tk.END)
    
    def toggle_password_visibility(self):
        """Bascule l'affichage du mot de passe."""
        if self.show_password_var.get():
            self.password_entry.configure(show='')
            self.confirm_entry.configure(show='')
        else:
            self.password_entry.configure(show='*')
            self.confirm_entry.configure(show='*')
    
    def validate_inputs(self):
        """Valide les entrées utilisateur."""
        if not self.selected_files:
            messagebox.showerror("Erreur", "Veuillez sélectionner au moins un fichier")
            return False
        
        password = self.password_var.get()
        if len(password) < 6:
            messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins 6 caractères")
            return False
        
        if self.operation_mode.get() == 'encrypt':
            if password != self.confirm_password_var.get():
                messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
                return False
        
        return True
    
    def start_operation(self):
        """Démarre l'opération de chiffrement/déchiffrement."""
        if not self.validate_inputs():
            return
        
        # Désactiver le bouton pendant l'opération
        self.action_button.configure(state='disabled')
        self.progress_var.set(0)
        
        # Démarrer l'opération dans un thread séparé
        threading.Thread(target=self.run_operation, daemon=True).start()
    
    def run_operation(self):
        """Exécute l'opération dans un thread séparé."""
        try:
            password = self.password_var.get()
            mode = self.operation_mode.get()
            
            success_count = 0
            error_count = 0
            
            for i, file_path in enumerate(self.selected_files):
                # Mettre à jour le progrès
                progress = (i / len(self.selected_files)) * 100
                self.update_progress(progress, f"Traitement {i+1}/{len(self.selected_files)}")
                
                if mode == 'encrypt':
                    if os.path.isdir(file_path):
                        # Chiffrement de dossier
                        output_path = filedialog.asksaveasfilename(
                            title=f"Sauvegarder l'archive chiffrée de {os.path.basename(file_path)}",
                            defaultextension=".fenc",
                            filetypes=[("Fichiers chiffrés", "*.fenc")]
                        )
                        
                        if output_path:
                            result = self.encryptor.encrypt_directory(
                                file_path, output_path, password, self.update_progress
                            )
                        else:
                            continue
                    else:
                        # Chiffrement de fichier
                        base_name = os.path.basename(file_path)
                        output_path = os.path.join(os.path.dirname(file_path), base_name + '.fenc')
                        
                        # Éviter l'écrasement
                        counter = 1
                        while os.path.exists(output_path):
                            name, ext = os.path.splitext(base_name)
                            output_path = os.path.join(
                                os.path.dirname(file_path), 
                                f"{name}_{counter}{ext}.fenc"
                            )
                            counter += 1
                        
                        result = self.encryptor.encrypt_file(
                            file_path, output_path, password, self.update_progress
                        )
                
                else:  # decrypt
                    # Déchiffrement
                    base_name = os.path.basename(file_path)
                    if base_name.endswith('.fenc'):
                        output_name = base_name[:-5]  # Retirer .fenc
                    else:
                        output_name = base_name + '_decrypted'
                    
                    output_path = os.path.join(os.path.dirname(file_path), output_name)
                    
                    # Éviter l'écrasement
                    counter = 1
                    while os.path.exists(output_path):
                        name, ext = os.path.splitext(output_name)
                        output_path = os.path.join(
                            os.path.dirname(file_path), 
                            f"{name}_{counter}{ext}"
                        )
                        counter += 1
                    
                    result = self.encryptor.decrypt_file(
                        file_path, output_path, password, self.update_progress
                    )
                
                if result['success']:
                    success_count += 1
                else:
                    error_count += 1
                    self.show_error(f"Erreur sur {os.path.basename(file_path)}: {result['error']}")
            
            # Opération terminée
            self.update_progress(100, f"Terminé: {success_count} succès, {error_count} erreurs")
            
            if success_count > 0:
                messagebox.showinfo("Opération terminée", 
                                  f"Opération réussie!\n{success_count} fichier(s) traité(s)")
            
            # Actualiser l'historique
            self.refresh_history()
            
        except Exception as e:
            self.show_error(f"Erreur inattendue: {str(e)}")
        
        finally:
            # Réactiver le bouton
            self.root.after(0, lambda: self.action_button.configure(state='normal'))
    
    def update_progress(self, value, message):
        """Met à jour la barre de progression et le message de statut."""
        self.root.after(0, lambda: self.progress_var.set(value))
        self.root.after(0, lambda: self.status_var.set(message))
    
    def show_error(self, message):
        """Affiche un message d'erreur de manière thread-safe."""
        self.root.after(0, lambda: messagebox.showerror("Erreur", message))
    
    def refresh_history(self):
        """Actualise l'affichage de l'historique."""
        self.history_text.delete('1.0', tk.END)
        
        if not self.encryptor.operations_log:
            self.history_text.insert(tk.END, "Aucune opération dans l'historique.")
            return
        
        # Trier par date (plus récent en premier)
        sorted_ops = sorted(self.encryptor.operations_log, 
                          key=lambda x: x.get('timestamp', ''), reverse=True)
        
        for op in sorted_ops[-50:]:  # Afficher les 50 dernières opérations
            timestamp = op.get('timestamp', 'N/A')[:19].replace('T', ' ')
            op_type = "🔒 Chiffrement" if op['type'] == 'encrypt' else "🔓 Déchiffrement"
            input_file = os.path.basename(op.get('input_file', 'N/A'))
            output_file = os.path.basename(op.get('output_file', 'N/A'))
            success = "✅" if op.get('success', False) else "❌"
            
            self.history_text.insert(tk.END, f"{timestamp} - {success} {op_type}\n")
            self.history_text.insert(tk.END, f"  Source: {input_file}\n")
            self.history_text.insert(tk.END, f"  Sortie: {output_file}\n")
            
            if 'file_size' in op:
                size_mb = op['file_size'] / (1024 * 1024)
                self.history_text.insert(tk.END, f"  Taille: {size_mb:.1f} MB\n")
            
            self.history_text.insert(tk.END, "\n")
        
        # Aller à la fin
        self.history_text.see(tk.END)
    
    def export_history(self):
        """Exporte l'historique vers un fichier."""
        filename = filedialog.asksaveasfilename(
            title="Exporter l'historique",
            defaultextension=".json",
            filetypes=[("Fichiers JSON", "*.json"), ("Fichiers texte", "*.txt")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.encryptor.operations_log, f, indent=2, ensure_ascii=False)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        for op in self.encryptor.operations_log:
                            f.write(f"{op.get('timestamp', 'N/A')} - {op['type']} - {op.get('input_file', 'N/A')}\n")
                
                messagebox.showinfo("Export réussi", f"Historique exporté vers {filename}")
            
            except Exception as e:
                messagebox.showerror("Erreur d'export", str(e))
    
    def clear_history(self):
        """Efface l'historique des opérations."""
        if messagebox.askyesno("Confirmation", "Effacer définitivement l'historique?"):
            self.encryptor.operations_log.clear()
            self.encryptor.save_operations_log()
            self.refresh_history()
            messagebox.showinfo("Historique effacé", "L'historique a été effacé avec succès")
    
    def run(self):
        """Lance l'application."""
        self.root.mainloop()


def main():
    """Fonction principale."""
    print("🔒 Chiffreur de Fichiers Personnel v1.0")
    print("=" * 50)
    
    try:
        app = FileEncryptorGUI()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication fermée par l'utilisateur")
    except Exception as e:
        print(f"Erreur inattendue: {e}")


if __name__ == "__main__":
    main()
