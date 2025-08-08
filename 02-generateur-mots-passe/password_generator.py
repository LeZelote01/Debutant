#!/usr/bin/env python3
"""
Générateur de Mots de Passe Sécurisés
====================================

Application web avec Flask pour générer des mots de passe sécurisés,
vérifier leur force et maintenir un historique chiffré.

Auteur: Jean Yves (LeZelote)
Date: Mai 2025
Version: 1.0
"""

import os
import random
import string
import secrets
import hashlib
import re
import json
from datetime import datetime
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, jsonify, send_from_directory

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

class PasswordGenerator:
    """Classe pour générer et analyser des mots de passe sécurisés."""
    
    def __init__(self):
        self.history_file = "password_history.json"
        self.key_file = "encryption_key.key"
        self.encryption_key = self._get_or_create_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _get_or_create_key(self):
        """Récupère ou crée une clé de chiffrement pour l'historique."""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def generate_password(self, length=12, include_uppercase=True, include_lowercase=True,
                         include_numbers=True, include_symbols=True, exclude_similar=True,
                         custom_words=None):
        """
        Génère un mot de passe selon les critères spécifiés.
        
        Args:
            length (int): Longueur du mot de passe
            include_uppercase (bool): Inclure les majuscules
            include_lowercase (bool): Inclure les minuscules
            include_numbers (bool): Inclure les chiffres
            include_symbols (bool): Inclure les symboles
            exclude_similar (bool): Exclure les caractères similaires (0,O,l,1,I)
            custom_words (list): Mots personnalisés à inclure
        
        Returns:
            dict: Mot de passe généré et ses métadonnées
        """
        if length < 4:
            raise ValueError("La longueur minimale est de 4 caractères")
        
        # Construction du jeu de caractères
        charset = ""
        
        if include_lowercase:
            chars = string.ascii_lowercase
            if exclude_similar:
                chars = chars.replace('l', '').replace('o', '')
            charset += chars
        
        if include_uppercase:
            chars = string.ascii_uppercase
            if exclude_similar:
                chars = chars.replace('I', '').replace('O', '')
            charset += chars
        
        if include_numbers:
            chars = string.digits
            if exclude_similar:
                chars = chars.replace('0', '').replace('1', '')
            charset += chars
        
        if include_symbols:
            symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
            charset += symbols
        
        if not charset:
            raise ValueError("Au moins un type de caractère doit être sélectionné")
        
        # Génération sécurisée du mot de passe
        password = ''.join(secrets.choice(charset) for _ in range(length))
        
        # Intégration de mots personnalisés si fournis
        if custom_words:
            # Remplacer une partie du mot de passe par un mot personnalisé
            word = secrets.choice(custom_words)
            if len(word) < length:
                start_pos = secrets.randbelow(length - len(word))
                password = password[:start_pos] + word + password[start_pos + len(word):]
        
        # Vérification et ajustement pour garantir la complexité
        password = self._ensure_complexity(password, include_uppercase, include_lowercase,
                                         include_numbers, include_symbols, charset)
        
        # Analyse de la force
        strength = self.analyze_password_strength(password)
        
        # Métadonnées
        metadata = {
            'password': password,
            'length': len(password),
            'strength': strength,
            'generated_at': datetime.now().isoformat(),
            'criteria': {
                'uppercase': include_uppercase,
                'lowercase': include_lowercase,
                'numbers': include_numbers,
                'symbols': include_symbols,
                'exclude_similar': exclude_similar,
                'custom_words_used': bool(custom_words)
            }
        }
        
        return metadata
    
    def _ensure_complexity(self, password, uppercase, lowercase, numbers, symbols, charset):
        """Garantit que le mot de passe respecte les critères de complexité."""
        password_list = list(password)
        
        # Vérifications et corrections
        if uppercase and not any(c.isupper() for c in password):
            pos = secrets.randbelow(len(password_list))
            upper_chars = [c for c in charset if c.isupper()]
            if upper_chars:
                password_list[pos] = secrets.choice(upper_chars)
        
        if lowercase and not any(c.islower() for c in password):
            pos = secrets.randbelow(len(password_list))
            lower_chars = [c for c in charset if c.islower()]
            if lower_chars:
                password_list[pos] = secrets.choice(lower_chars)
        
        if numbers and not any(c.isdigit() for c in password):
            pos = secrets.randbelow(len(password_list))
            digit_chars = [c for c in charset if c.isdigit()]
            if digit_chars:
                password_list[pos] = secrets.choice(digit_chars)
        
        if symbols and not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
            pos = secrets.randbelow(len(password_list))
            symbol_chars = [c for c in charset if c in "!@#$%^&*()_+-=[]{}|;':\",./<>?"]
            if symbol_chars:
                password_list[pos] = secrets.choice(symbol_chars)
        
        return ''.join(password_list)
    
    def analyze_password_strength(self, password):
        """
        Analyse la force d'un mot de passe.
        
        Args:
            password (str): Mot de passe à analyser
        
        Returns:
            dict: Analyse détaillée de la force
        """
        if not password:
            return {'score': 0, 'level': 'Très Faible', 'feedback': ['Mot de passe vide']}
        
        score = 0
        feedback = []
        
        # Longueur
        length = len(password)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
            feedback.append("Augmentez la longueur à 12+ caractères pour plus de sécurité")
        else:
            score += 5
            feedback.append("Mot de passe trop court (minimum 8 caractères)")
        
        # Variété des caractères
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        char_variety = sum([has_lower, has_upper, has_digit, has_symbol])
        score += char_variety * 10
        
        if not has_lower:
            feedback.append("Ajoutez des lettres minuscules")
        if not has_upper:
            feedback.append("Ajoutez des lettres majuscules")
        if not has_digit:
            feedback.append("Ajoutez des chiffres")
        if not has_symbol:
            feedback.append("Ajoutez des symboles (!@#$%...)")
        
        # Motifs répétitifs
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("Évitez les caractères répétés")
        
        # Séquences communes
        common_sequences = ['123', 'abc', 'qwerty', 'password', 'admin']
        for seq in common_sequences:
            if seq.lower() in password.lower():
                score -= 15
                feedback.append(f"Évitez les séquences communes comme '{seq}'")
        
        # Calcul du niveau
        if score >= 80:
            level = "Très Fort"
            color = "success"
        elif score >= 60:
            level = "Fort"
            color = "info"
        elif score >= 40:
            level = "Moyen"
            color = "warning"
        elif score >= 20:
            level = "Faible"
            color = "danger"
        else:
            level = "Très Faible"
            color = "danger"
        
        # Estimation du temps de crack
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32
        
        if charset_size > 0:
            combinations = charset_size ** length
            # Estimation basée sur 1 milliard de tentatives par seconde
            seconds = combinations / (2 * 1_000_000_000)
            crack_time = self._format_crack_time(seconds)
        else:
            crack_time = "Incalculable"
        
        return {
            'score': max(0, min(100, score)),
            'level': level,
            'color': color,
            'feedback': feedback,
            'crack_time': crack_time,
            'details': {
                'length': length,
                'has_lowercase': has_lower,
                'has_uppercase': has_upper,
                'has_digits': has_digit,
                'has_symbols': has_symbol,
                'char_variety': char_variety
            }
        }
    
    def _format_crack_time(self, seconds):
        """Formate le temps de crack en unités lisibles."""
        if seconds < 60:
            return f"{seconds:.1f} secondes"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} heures"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} jours"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} années"
        else:
            return "Plusieurs siècles"
    
    def save_to_history(self, password_data):
        """Sauvegarde un mot de passe dans l'historique chiffré."""
        try:
            # Charger l'historique existant
            history = self._load_history()
            
            # Chiffrer le mot de passe
            encrypted_password = self.fernet.encrypt(password_data['password'].encode())
            
            # Créer l'entrée d'historique (sans le mot de passe en clair)
            history_entry = {
                'id': len(history) + 1,
                'encrypted_password': encrypted_password.decode(),
                'length': password_data['length'],
                'strength_score': password_data['strength']['score'],
                'strength_level': password_data['strength']['level'],
                'generated_at': password_data['generated_at'],
                'criteria': password_data['criteria']
            }
            
            history.append(history_entry)
            
            # Limiter l'historique à 100 entrées
            if len(history) > 100:
                history = history[-100:]
            
            # Sauvegarder
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print(f"Erreur sauvegarde historique: {e}")
            return False
    
    def _load_history(self):
        """Charge l'historique des mots de passe."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def get_history_summary(self):
        """Récupère un résumé de l'historique (sans les mots de passe)."""
        history = self._load_history()
        
        # Statistiques générales
        if not history:
            return {
                'total': 0,
                'entries': [],
                'stats': {}
            }
        
        # Calcul des statistiques
        strength_distribution = {}
        avg_length = 0
        avg_score = 0
        
        for entry in history:
            level = entry['strength_level']
            strength_distribution[level] = strength_distribution.get(level, 0) + 1
            avg_length += entry['length']
            avg_score += entry['strength_score']
        
        if history:
            avg_length /= len(history)
            avg_score /= len(history)
        
        return {
            'total': len(history),
            'entries': [
                {
                    'id': entry['id'],
                    'length': entry['length'],
                    'strength_level': entry['strength_level'],
                    'strength_score': entry['strength_score'],
                    'generated_at': entry['generated_at'][:19].replace('T', ' '),
                    'has_password': True  # Indique qu'un mot de passe chiffré existe
                }
                for entry in reversed(history[-20:])  # 20 dernières entrées
            ],
            'stats': {
                'avg_length': round(avg_length, 1),
                'avg_score': round(avg_score, 1),
                'strength_distribution': strength_distribution
            }
        }

# Instance globale du générateur
generator = PasswordGenerator()

# Routes Flask
@app.route('/')
def index():
    """Page principale de l'application."""
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_password():
    """API pour générer un mot de passe."""
    try:
        data = request.get_json()
        
        # Paramètres avec valeurs par défaut
        params = {
            'length': data.get('length', 12),
            'include_uppercase': data.get('uppercase', True),
            'include_lowercase': data.get('lowercase', True),
            'include_numbers': data.get('numbers', True),
            'include_symbols': data.get('symbols', True),
            'exclude_similar': data.get('exclude_similar', True),
            'custom_words': data.get('custom_words', [])
        }
        
        # Validation des paramètres
        if params['length'] < 4 or params['length'] > 128:
            return jsonify({'error': 'Longueur doit être entre 4 et 128'}), 400
        
        # Génération du mot de passe
        result = generator.generate_password(**params)
        
        # Sauvegarde dans l'historique si demandée
        if data.get('save_to_history', False):
            generator.save_to_history(result)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze_password():
    """API pour analyser la force d'un mot de passe."""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Mot de passe requis'}), 400
        
        analysis = generator.analyze_password_strength(password)
        return jsonify(analysis)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def get_history():
    """API pour récupérer l'historique des mots de passe."""
    try:
        history = generator.get_history_summary()
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Sert les fichiers statiques."""
    return send_from_directory('static', filename)

if __name__ == '__main__':
    # Créer le dossier static s'il n'existe pas
    os.makedirs('static', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    print("🔐 Générateur de Mots de Passe Sécurisés v1.0")
    print("=" * 50)
    print("🌐 Application web démarrée sur http://localhost:5000")
    print("📊 Interface responsive avec Bootstrap")
    print("🔒 Historique chiffré des mots de passe")
    print("\nAppuyez sur Ctrl+C pour arrêter")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
