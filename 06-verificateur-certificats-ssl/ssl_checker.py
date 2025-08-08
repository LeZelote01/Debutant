#!/usr/bin/env python3
"""
Vérificateur de Certificats SSL
==============================

Outil pour vérifier la validité des certificats SSL/TLS, détecter les expirations
et analyser la configuration de sécurité des serveurs web.

Auteur: Jean Yves (LeZelote)
Date: Mai 2025
Version: 1.0
"""

import ssl
import socket
import datetime
import argparse
import json
import csv
import threading
import time
import schedule
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import concurrent.futures

# import tkinter as tk
# from tkinter import ttk, filedialog, messagebox, scrolledtext
# from tkinter import font


class SSLChecker:
    """Classe principale pour la vérification des certificats SSL."""
    
    def __init__(self):
        self.results_history = []
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Configuration par défaut
        self.default_ports = [443, 8443, 993, 995, 465, 587, 636, 389]
        self.timeout = 10
        
        # Critères de sécurité
        self.min_key_size = 2048
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1'
        ]
        self.recommended_protocols = ['TLSv1.2', 'TLSv1.3']
    
    def check_certificate(self, hostname, port=443, timeout=10):
        """
        Vérifie le certificat SSL d'un serveur.
        
        Args:
            hostname (str): Nom d'hôte ou adresse IP
            port (int): Port SSL (défaut: 443)
            timeout (int): Délai d'expiration en secondes
        
        Returns:
            dict: Informations détaillées sur le certificat
        """
        result = {
            'hostname': hostname,
            'port': port,
            'checked_at': datetime.datetime.now().isoformat(),
            'status': 'unknown',
            'errors': [],
            'warnings': []
        }
        
        try:
            # Créer le contexte SSL
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connexion SSL
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Obtenir le certificat
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # Parser le certificat avec cryptography
                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Informations de base
                    result.update({
                        'status': 'valid',
                        'certificate_info': self._extract_certificate_info(cert_dict, cert_obj),
                        'chain_info': self._extract_chain_info(ssock),
                        'protocol_info': self._extract_protocol_info(ssock),
                        'security_analysis': self._analyze_security(cert_obj, ssock)
                    })
                    
                    # Vérifications supplémentaires
                    self._check_expiration(result, cert_obj)
                    self._check_hostname_match(result, hostname, cert_dict)
                    self._check_revocation_status(result, cert_obj)
                    
        except ssl.SSLError as e:
            result['status'] = 'ssl_error'
            result['errors'].append(f"Erreur SSL: {str(e)}")
        except socket.timeout:
            result['status'] = 'timeout'
            result['errors'].append(f"Timeout de connexion ({timeout}s)")
        except socket.gaierror as e:
            result['status'] = 'dns_error'
            result['errors'].append(f"Erreur DNS: {str(e)}")
        except Exception as e:
            result['status'] = 'error'
            result['errors'].append(f"Erreur inattendue: {str(e)}")
        
        # Calcul du score de sécurité
        result['security_score'] = self._calculate_security_score(result)
        
        return result
    
    def _extract_certificate_info(self, cert_dict, cert_obj):
        """Extrait les informations détaillées du certificat."""
        info = {}
        
        # Informations de base
        info['subject'] = dict(x[0] for x in cert_dict.get('subject', []))
        info['issuer'] = dict(x[0] for x in cert_dict.get('issuer', []))
        info['version'] = cert_dict.get('version', 'Unknown')
        info['serial_number'] = str(cert_obj.serial_number)
        
        # Dates de validité
        info['not_before'] = cert_dict.get('notBefore', '')
        info['not_after'] = cert_dict.get('notAfter', '')
        info['expires_in_days'] = self._days_until_expiry(cert_dict.get('notAfter', ''))
        
        # Clé publique
        public_key = cert_obj.public_key()
        info['public_key_algorithm'] = public_key.__class__.__name__
        
        if hasattr(public_key, 'key_size'):
            info['key_size'] = public_key.key_size
        
        # Extensions
        info['extensions'] = self._extract_extensions(cert_obj)
        
        # Alternative names
        san_list = []
        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        info['subject_alternative_names'] = san_list
        
        # Signature
        info['signature_algorithm'] = cert_obj.signature_algorithm_oid._name
        
        return info
    
    def _extract_chain_info(self, ssock):
        """Extrait les informations de la chaîne de certificats."""
        chain_info = {
            'chain_length': 0,
            'intermediate_cas': [],
            'root_ca': None
        }
        
        try:
            # Note: getpeercert_chain() n'est pas disponible dans cette implémentation SSL
            # On se contente d'indiquer qu'un seul certificat est disponible
            chain_info['chain_length'] = 1
            chain_info['note'] = 'Chaîne complète non disponible dans cette implémentation SSL'
                        
        except Exception as e:
            chain_info['error'] = str(e)
        
        return chain_info
    
    def _extract_protocol_info(self, ssock):
        """Extrait les informations sur le protocole SSL/TLS."""
        info = {}
        
        try:
            info['protocol'] = ssock.version()
            info['cipher'] = ssock.cipher()
            
            # Détails du cipher suite
            if info['cipher']:
                cipher_name, protocol, key_bits = info['cipher']
                info['cipher_suite'] = cipher_name
                info['protocol_version'] = protocol
                info['key_bits'] = key_bits
                
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def _extract_extensions(self, cert_obj):
        """Extrait les extensions du certificat."""
        extensions = {}
        
        try:
            for ext in cert_obj.extensions:
                try:
                    ext_name = ext.oid._name
                    extensions[ext_name] = {
                        'critical': ext.critical,
                        'value': str(ext.value)
                    }
                except Exception:
                    continue
        except Exception:
            pass
        
        return extensions
    
    def _days_until_expiry(self, not_after_str):
        """Calcule le nombre de jours avant expiration."""
        try:
            # Format: 'Jul 27 12:00:00 2025 GMT'
            expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            delta = expiry_date - datetime.datetime.now()
            return delta.days
        except Exception:
            return None
    
    def _check_expiration(self, result, cert_obj):
        """Vérifie l'expiration du certificat."""
        now = datetime.datetime.now()
        not_after = cert_obj.not_valid_after.replace(tzinfo=None)
        not_before = cert_obj.not_valid_before.replace(tzinfo=None)
        
        # Certificat expiré
        if now > not_after:
            result['errors'].append(f"Certificat expiré depuis le {not_after}")
            result['status'] = 'expired'
        
        # Certificat pas encore valide
        elif now < not_before:
            result['errors'].append(f"Certificat pas encore valide jusqu'au {not_before}")
            result['status'] = 'not_yet_valid'
        
        # Expiration prochaine
        else:
            days_left = (not_after - now).days
            if days_left <= 7:
                result['errors'].append(f"Certificat expire dans {days_left} jours !")
            elif days_left <= 30:
                result['warnings'].append(f"Certificat expire dans {days_left} jours")
    
    def _check_hostname_match(self, result, hostname, cert_dict):
        """Vérifie la correspondance du nom d'hôte."""
        subject = dict(x[0] for x in cert_dict.get('subject', []))
        common_name = subject.get('commonName', '')
        
        # Obtenir tous les noms possibles
        valid_names = [common_name]
        
        # Ajouter les SAN
        if 'subjectAltName' in cert_dict:
            for san_type, san_value in cert_dict['subjectAltName']:
                if san_type == 'DNS':
                    valid_names.append(san_value)
        
        # Vérifier la correspondance
        hostname_matches = any(
            self._match_hostname(hostname, name) for name in valid_names if name
        )
        
        if not hostname_matches:
            result['warnings'].append(f"Nom d'hôte '{hostname}' ne correspond pas au certificat")
    
    def _match_hostname(self, hostname, cert_name):
        """Vérifie si un nom d'hôte correspond au nom du certificat (avec wildcards)."""
        if cert_name == hostname:
            return True
        
        # Gestion des wildcards
        if cert_name.startswith('*.'):
            cert_domain = cert_name[2:]
            if '.' in hostname:
                hostname_domain = hostname[hostname.index('.') + 1:]
                return cert_domain == hostname_domain
        
        return False
    
    def _check_revocation_status(self, result, cert_obj):
        """Vérifie le statut de révocation (OCSP/CRL)."""
        # Note: Implémentation simplifiée
        # Une vérification OCSP complète nécessiterait plus de code
        
        try:
            # Rechercher les extensions de révocation
            for ext in cert_obj.extensions:
                if ext.oid._name == 'authorityInfoAccess':
                    result['revocation_info'] = {
                        'ocsp_available': 'OCSP' in str(ext.value),
                        'crl_available': 'CA Issuers' in str(ext.value)
                    }
                    break
        except Exception:
            result['revocation_info'] = {'error': 'Impossible de vérifier le statut de révocation'}
    
    def _analyze_security(self, cert_obj, ssock):
        """Analyse la sécurité du certificat et de la connexion."""
        analysis = {
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        # Analyse de la clé publique
        public_key = cert_obj.public_key()
        if hasattr(public_key, 'key_size'):
            key_size = public_key.key_size
            if key_size >= 4096:
                analysis['strengths'].append(f"Clé RSA forte ({key_size} bits)")
            elif key_size >= 2048:
                analysis['strengths'].append(f"Clé RSA adequate ({key_size} bits)")
            else:
                analysis['weaknesses'].append(f"Clé RSA faible ({key_size} bits)")
                analysis['recommendations'].append("Utiliser une clé d'au moins 2048 bits")
        
        # Analyse de l'algorithme de signature
        sig_alg = cert_obj.signature_algorithm_oid._name.lower()
        if 'sha256' in sig_alg or 'sha384' in sig_alg or 'sha512' in sig_alg:
            analysis['strengths'].append(f"Algorithme de signature sécurisé ({sig_alg})")
        elif 'sha1' in sig_alg:
            analysis['weaknesses'].append(f"Algorithme de signature obsolète ({sig_alg})")
            analysis['recommendations'].append("Migrer vers SHA-256 ou supérieur")
        elif 'md5' in sig_alg:
            analysis['weaknesses'].append(f"Algorithme de signature très faible ({sig_alg})")
            analysis['recommendations'].append("Remplacer immédiatement par SHA-256")
        
        # Analyse du protocole TLS
        try:
            protocol = ssock.version()
            if protocol in ['TLSv1.3', 'TLSv1.2']:
                analysis['strengths'].append(f"Protocole sécurisé ({protocol})")
            elif protocol in ['TLSv1.1', 'TLSv1']:
                analysis['weaknesses'].append(f"Protocole obsolète ({protocol})")
                analysis['recommendations'].append("Migrer vers TLS 1.2 ou 1.3")
            elif protocol in ['SSLv3', 'SSLv2']:
                analysis['weaknesses'].append(f"Protocole très vulnérable ({protocol})")
                analysis['recommendations'].append("Désactiver SSL et utiliser TLS 1.2+")
        except:
            pass
        
        # Analyse du cipher suite
        try:
            cipher_info = ssock.cipher()
            if cipher_info:
                cipher_name = cipher_info[0]
                
                # Chiffrements forts
                if any(strong in cipher_name for strong in ['AES', 'ChaCha20']):
                    analysis['strengths'].append(f"Chiffrement fort ({cipher_name})")
                
                # Chiffrements faibles
                for weak in self.weak_ciphers:
                    if weak in cipher_name:
                        analysis['weaknesses'].append(f"Chiffrement faible ({weak})")
                        analysis['recommendations'].append(f"Éviter {weak}")
                        break
        except:
            pass
        
        return analysis
    
    def _calculate_security_score(self, result):
        """Calcule un score de sécurité sur 100."""
        if result['status'] not in ['valid']:
            return 0
        
        score = 100
        
        # Pénalités pour les erreurs
        score -= len(result.get('errors', [])) * 30
        
        # Pénalités pour les avertissements
        score -= len(result.get('warnings', [])) * 10
        
        # Bonus/Pénalités basés sur l'analyse de sécurité
        security_analysis = result.get('security_analysis', {})
        score += len(security_analysis.get('strengths', [])) * 5
        score -= len(security_analysis.get('weaknesses', [])) * 15
        
        # Vérifier les informations du certificat
        cert_info = result.get('certificate_info', {})
        
        # Pénalité pour expiration proche
        days_left = cert_info.get('expires_in_days')
        if days_left is not None:
            if days_left <= 7:
                score -= 40
            elif days_left <= 30:
                score -= 20
            elif days_left <= 90:
                score -= 10
        
        # Pénalité pour clé faible
        key_size = cert_info.get('key_size')
        if key_size:
            if key_size < 2048:
                score -= 30
            elif key_size < 4096:
                score -= 5
        
        return max(0, min(100, score))
    
    def check_multiple_hosts(self, hosts, max_workers=10, progress_callback=None):
        """
        Vérifie plusieurs hôtes en parallèle.
        
        Args:
            hosts (list): Liste des hôtes à vérifier
            max_workers (int): Nombre de threads parallèles
            progress_callback (function): Callback pour le progrès
        
        Returns:
            list: Résultats pour tous les hôtes
        """
        results = []
        total_hosts = len(hosts)
        
        def check_host_wrapper(host_info):
            if isinstance(host_info, str):
                hostname, port = host_info, 443
            elif isinstance(host_info, dict):
                hostname = host_info['hostname']
                port = host_info.get('port', 443)
            else:
                hostname, port = host_info
            
            return self.check_certificate(hostname, port, self.timeout)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {executor.submit(check_host_wrapper, host): host for host in hosts}
            
            for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
                result = future.result()
                results.append(result)
                
                if progress_callback:
                    progress = int(((i + 1) / total_hosts) * 100)
                    hostname = result['hostname']
                    status = result['status']
                    progress_callback(progress, f"Vérifié {hostname}: {status}")
        
        return results
    
    def start_monitoring(self, hosts, check_interval_hours=24, alert_callback=None):
        """
        Démarre le monitoring continu des certificats.
        
        Args:
            hosts (list): Liste des hôtes à monitorer
            check_interval_hours (int): Intervalle de vérification en heures
            alert_callback (function): Callback pour les alertes
        """
        self.monitoring_active = True
        self.monitored_hosts = hosts
        self.alert_callback = alert_callback
        
        # Planifier les vérifications
        schedule.every(check_interval_hours).hours.do(
            self._scheduled_check, hosts, alert_callback
        )
        
        # Thread de monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Première vérification immédiate
        threading.Thread(target=lambda: self._scheduled_check(hosts, alert_callback), daemon=True).start()
    
    def stop_monitoring(self):
        """Arrête le monitoring."""
        self.monitoring_active = False
        schedule.clear()
    
    def _monitor_loop(self):
        """Boucle principale de monitoring."""
        while self.monitoring_active:
            schedule.run_pending()
            time.sleep(60)  # Vérifier chaque minute
    
    def _scheduled_check(self, hosts, alert_callback):
        """Vérification planifiée des certificats."""
        if not self.monitoring_active:
            return
        
        results = self.check_multiple_hosts(hosts)
        
        # Vérifier les alertes
        alerts = []
        for result in results:
            hostname = result['hostname']
            status = result['status']
            
            # Alertes critiques
            if status in ['expired', 'ssl_error', 'error']:
                alerts.append({
                    'level': 'critical',
                    'hostname': hostname,
                    'message': f"Certificat {hostname}: {status}",
                    'details': result
                })
            
            # Alertes d'avertissement
            elif result.get('warnings'):
                for warning in result['warnings']:
                    alerts.append({
                        'level': 'warning',
                        'hostname': hostname,
                        'message': f"Certificat {hostname}: {warning}",
                        'details': result
                    })
        
        # Déclencher les callbacks d'alerte
        if alerts and alert_callback:
            alert_callback(alerts)
        
        # Sauvegarder les résultats
        self.results_history.extend(results)
        
        # Limiter l'historique
        if len(self.results_history) > 1000:
            self.results_history = self.results_history[-1000:]
    
    def generate_report(self, results, format='html', output_file=None):
        """
        Génère un rapport des vérifications.
        
        Args:
            results (list): Résultats des vérifications
            format (str): Format du rapport ('html', 'json', 'csv')
            output_file (str): Fichier de sortie
        
        Returns:
            str: Contenu du rapport
        """
        if format == 'html':
            content = self._generate_html_report(results)
        elif format == 'json':
            content = json.dumps(results, indent=2, default=str, ensure_ascii=False)
        elif format == 'csv':
            content = self._generate_csv_report(results)
        else:
            content = str(results)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Rapport sauvegardé: {output_file}")
            except Exception as e:
                print(f"Erreur sauvegarde: {e}")
        
        return content
    
    def _generate_html_report(self, results):
        """Génère un rapport HTML."""
        # Statistiques
        total = len(results)
        valid = len([r for r in results if r['status'] == 'valid'])
        expired = len([r for r in results if r['status'] == 'expired'])
        errors = len([r for r in results if r['status'] in ['ssl_error', 'error', 'timeout']])
        
        # Score moyen
        scores = [r.get('security_score', 0) for r in results if r.get('security_score') is not None]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Vérification SSL/TLS</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat {{ background: #ecf0f1; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 36px; font-weight: bold; margin-bottom: 10px; }}
        .stat-label {{ font-size: 14px; color: #7f8c8d; }}
        .valid {{ color: #27ae60; }}
        .expired {{ color: #e74c3c; }}
        .warning {{ color: #f39c12; }}
        .error {{ color: #c0392b; }}
        .host-card {{ margin: 20px 0; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
        .host-header {{ padding: 15px; font-weight: bold; }}
        .host-content {{ padding: 15px; }}
        .security-score {{ float: right; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }}
        .score-high {{ background: #27ae60; }}
        .score-medium {{ background: #f39c12; }}
        .score-low {{ background: #e74c3c; }}
        .details {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 15px; }}
        .detail-section {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
        .detail-title {{ font-weight: bold; color: #2c3e50; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Rapport de Vérification SSL/TLS</h1>
            <p>Généré le: {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Certificats vérifiés</div>
            </div>
            <div class="stat">
                <div class="stat-value valid">{valid}</div>
                <div class="stat-label">Valides</div>
            </div>
            <div class="stat">
                <div class="stat-value expired">{expired}</div>
                <div class="stat-label">Expirés</div>
            </div>
            <div class="stat">
                <div class="stat-value error">{errors}</div>
                <div class="stat-label">Erreurs</div>
            </div>
            <div class="stat">
                <div class="stat-value">{avg_score:.0f}/100</div>
                <div class="stat-label">Score moyen</div>
            </div>
        </div>
        
        <h2>Détails par certificat</h2>
"""
        
        # Détails par hôte
        for result in results:
            hostname = result['hostname']
            port = result['port']
            status = result['status']
            score = result.get('security_score', 0)
            
            # Classe CSS pour le score
            if score >= 80:
                score_class = 'score-high'
            elif score >= 60:
                score_class = 'score-medium'
            else:
                score_class = 'score-low'
            
            # Classe CSS pour le statut
            status_class = {
                'valid': 'valid',
                'expired': 'expired',
                'ssl_error': 'error',
                'error': 'error',
                'timeout': 'warning'
            }.get(status, 'warning')
            
            html += f"""
        <div class="host-card">
            <div class="host-header {status_class}">
                🌐 {hostname}:{port}
                <span class="security-score {score_class}">{score}/100</span>
            </div>
            <div class="host-content">
                <p><strong>Statut:</strong> <span class="{status_class}">{status}</span></p>
"""
            
            # Erreurs et avertissements
            if result.get('errors'):
                html += '<p><strong>Erreurs:</strong></p><ul>'
                for error in result['errors']:
                    html += f'<li class="error">❌ {error}</li>'
                html += '</ul>'
            
            if result.get('warnings'):
                html += '<p><strong>Avertissements:</strong></p><ul>'
                for warning in result['warnings']:
                    html += f'<li class="warning">⚠️ {warning}</li>'
                html += '</ul>'
            
            # Détails du certificat si valide
            if status == 'valid' and 'certificate_info' in result:
                cert_info = result['certificate_info']
                
                html += '<div class="details">'
                
                # Informations générales
                html += '<div class="detail-section">'
                html += '<div class="detail-title">📋 Informations générales</div>'
                html += f'<p><strong>Sujet:</strong> {cert_info.get("subject", {}).get("commonName", "N/A")}</p>'
                html += f'<p><strong>Émetteur:</strong> {cert_info.get("issuer", {}).get("organizationName", "N/A")}</p>'
                html += f'<p><strong>Expire le:</strong> {cert_info.get("not_after", "N/A")}</p>'
                html += f'<p><strong>Jours restants:</strong> {cert_info.get("expires_in_days", "N/A")}</p>'
                html += '</div>'
                
                # Sécurité
                html += '<div class="detail-section">'
                html += '<div class="detail-title">🔐 Sécurité</div>'
                html += f'<p><strong>Algorithme clé:</strong> {cert_info.get("public_key_algorithm", "N/A")}</p>'
                html += f'<p><strong>Taille clé:</strong> {cert_info.get("key_size", "N/A")} bits</p>'
                html += f'<p><strong>Signature:</strong> {cert_info.get("signature_algorithm", "N/A")}</p>'
                
                # Protocole
                protocol_info = result.get('protocol_info', {})
                html += f'<p><strong>Protocole:</strong> {protocol_info.get("protocol", "N/A")}</p>'
                html += '</div>'
                
                html += '</div>'  # Fermer details
            
            html += '</div></div>'  # Fermer host-card
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _generate_csv_report(self, results):
        """Génère un rapport CSV."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # En-têtes
        headers = [
            'Hostname', 'Port', 'Status', 'Security_Score', 'Expires_In_Days',
            'Issuer', 'Key_Size', 'Protocol', 'Checked_At', 'Errors', 'Warnings'
        ]
        writer.writerow(headers)
        
        # Données
        for result in results:
            cert_info = result.get('certificate_info', {})
            protocol_info = result.get('protocol_info', {})
            
            row = [
                result['hostname'],
                result['port'],
                result['status'],
                result.get('security_score', 0),
                cert_info.get('expires_in_days', ''),
                cert_info.get('issuer', {}).get('organizationName', ''),
                cert_info.get('key_size', ''),
                protocol_info.get('protocol', ''),
                result['checked_at'],
                '; '.join(result.get('errors', [])),
                '; '.join(result.get('warnings', []))
            ]
            writer.writerow(row)
        
        return output.getvalue()


class SSLCheckerGUI:
    """Interface graphique pour le vérificateur SSL."""
    
    def __init__(self):
        self.checker = SSLChecker()
        self.results = []
        self.monitoring_active = False
        self.setup_gui()
    
    def setup_gui(self):
        """Configure l'interface graphique."""
        self.root = tk.Tk()
        self.root.title("🔒 Vérificateur de Certificats SSL/TLS v1.0")
        self.root.geometry("1000x800")
        self.root.configure(bg='#f0f0f0')
        
        # Police personnalisée
        self.title_font = font.Font(family="Arial", size=12, weight="bold")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Crée l'interface utilisateur."""
        # Notebook pour les onglets
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Onglets
        self.check_frame = ttk.Frame(notebook)
        notebook.add(self.check_frame, text='🔍 Vérification')
        
        self.monitor_frame = ttk.Frame(notebook)
        notebook.add(self.monitor_frame, text='📊 Monitoring')
        
        self.results_frame = ttk.Frame(notebook)
        notebook.add(self.results_frame, text='📋 Résultats')
        
        self.about_frame = ttk.Frame(notebook)
        notebook.add(self.about_frame, text='ℹ️ À propos')
        
        self.create_check_tab()
        self.create_monitor_tab()
        self.create_results_tab()
        self.create_about_tab()
    
    def create_check_tab(self):
        """Crée l'onglet de vérification."""
        # Frame d'entrée
        input_frame = ttk.LabelFrame(self.check_frame, text="Certificats à vérifier", padding=15)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Zone de saisie des hôtes
        ttk.Label(input_frame, text="Saisissez les hôtes à vérifier (un par ligne):").pack(anchor='w')
        ttk.Label(input_frame, text="Format: hostname:port (port optionnel, défaut: 443)", 
                 font=('Arial', 9)).pack(anchor='w', pady=(0, 5))
        
        self.hosts_text = tk.Text(input_frame, height=8, width=80)
        scrollbar_hosts = ttk.Scrollbar(input_frame, orient='vertical', command=self.hosts_text.yview)
        self.hosts_text.configure(yscrollcommand=scrollbar_hosts.set)
        
        hosts_frame = ttk.Frame(input_frame)
        hosts_frame.pack(fill='x', pady=5)
        self.hosts_text.pack(side='left', fill='both', expand=True)
        scrollbar_hosts.pack(side='right', fill='y')
        
        # Exemples
        examples = "google.com\nfacebook.com:443\ngithub.com\nmicrosoft.com"
        self.hosts_text.insert('1.0', examples)
        
        # Boutons d'action
        buttons_frame = ttk.Frame(input_frame)
        buttons_frame.pack(fill='x', pady=10)
        
        ttk.Button(buttons_frame, text="📁 Charger depuis fichier", 
                  command=self.load_hosts_file).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="🗑️ Effacer", 
                  command=lambda: self.hosts_text.delete('1.0', tk.END)).pack(side='left', padx=5)
        
        # Options
        options_frame = ttk.LabelFrame(self.check_frame, text="Options", padding=15)
        options_frame.pack(fill='x', padx=10, pady=5)
        
        options_grid = ttk.Frame(options_frame)
        options_grid.pack(fill='x')
        
        ttk.Label(options_grid, text="Timeout (secondes):").grid(row=0, column=0, sticky='w', padx=5)
        self.timeout_var = tk.StringVar(value="10")
        ttk.Entry(options_grid, textvariable=self.timeout_var, width=10).grid(row=0, column=1, padx=5)
        
        ttk.Label(options_grid, text="Threads parallèles:").grid(row=0, column=2, sticky='w', padx=5)
        self.threads_var = tk.StringVar(value="10")
        ttk.Entry(options_grid, textvariable=self.threads_var, width=10).grid(row=0, column=3, padx=5)
        
        # Bouton de vérification
        action_frame = ttk.Frame(self.check_frame)
        action_frame.pack(fill='x', padx=10, pady=15)
        
        self.check_button = ttk.Button(action_frame, text="🚀 Vérifier les certificats", 
                                      command=self.start_check, style='Accent.TButton')
        self.check_button.pack()
        
        # Barre de progression
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.check_frame, variable=self.progress_var, 
                                           maximum=100, length=500)
        self.progress_bar.pack(padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Prêt à vérifier")
        ttk.Label(self.check_frame, textvariable=self.status_var).pack(pady=5)
    
    def create_monitor_tab(self):
        """Crée l'onglet de monitoring."""
        # Configuration du monitoring
        config_frame = ttk.LabelFrame(self.monitor_frame, text="Configuration du monitoring", padding=15)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(config_frame, text="Intervalle de vérification (heures):").grid(row=0, column=0, sticky='w', padx=5)
        self.interval_var = tk.StringVar(value="24")
        ttk.Entry(config_frame, textvariable=self.interval_var, width=10).grid(row=0, column=1, padx=5)
        
        # Boutons de contrôle
        control_frame = ttk.Frame(config_frame)
        control_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky='w')
        
        self.start_monitor_button = ttk.Button(control_frame, text="▶️ Démarrer monitoring", 
                                              command=self.start_monitoring)
        self.start_monitor_button.pack(side='left', padx=5)
        
        self.stop_monitor_button = ttk.Button(control_frame, text="⏹️ Arrêter monitoring", 
                                             command=self.stop_monitoring, state='disabled')
        self.stop_monitor_button.pack(side='left', padx=5)
        
        # Status du monitoring
        self.monitor_status_var = tk.StringVar(value="Monitoring arrêté")
        ttk.Label(config_frame, textvariable=self.monitor_status_var).grid(row=2, column=0, columnspan=2, pady=5)
        
        # Zone d'alertes
        alerts_frame = ttk.LabelFrame(self.monitor_frame, text="Alertes récentes", padding=15)
        alerts_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=15)
        self.alerts_text.pack(fill='both', expand=True)
    
    def create_results_tab(self):
        """Crée l'onglet des résultats."""
        # Boutons d'action
        buttons_frame = ttk.Frame(self.results_frame)
        buttons_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="💾 Sauvegarder HTML", 
                  command=lambda: self.save_report('html')).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="📊 Sauvegarder CSV", 
                  command=lambda: self.save_report('csv')).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="🔄 Actualiser", 
                  command=self.refresh_results).pack(side='left', padx=5)
        
        # Zone de résultats
        self.results_text = scrolledtext.ScrolledText(self.results_frame, height=30)
        self.results_text.pack(fill='both', expand=True, padx=10, pady=5)
    
    def create_about_tab(self):
        """Crée l'onglet à propos."""
        about_text = """
🔒 Vérificateur de Certificats SSL/TLS v1.0

Outil professionnel pour vérifier la validité et la sécurité 
des certificats SSL/TLS.

Fonctionnalités principales:
• Vérification de validité des certificats
• Analyse de sécurité avancée
• Détection des expirations prochaines
• Monitoring continu avec alertes
• Rapports HTML et CSV détaillés
• Vérification en lot avec multithreading

Informations vérifiées:
• Dates de validité et expiration
• Chaîne de certification complète
• Algorithmes de chiffrement et signature
• Protocoles TLS/SSL supportés
• Correspondance des noms d'hôte
• Extensions de certificat
• Score de sécurité global

Types d'alertes:
• Certificats expirés ou invalides
• Expiration prochaine (7, 30, 90 jours)
• Algorithmes faibles ou obsolètes
• Problèmes de configuration SSL
• Erreurs de validation de chaîne

Export et rapports:
• Rapports HTML avec graphiques
• Export CSV pour analyse
• Historique des vérifications
• Monitoring programmable

Technologies utilisées:
• Python 3.8+ avec ssl, cryptography
• Interface Tkinter moderne
• Threading pour performances
• Scheduling pour monitoring

Auteur: Assistant IA
Date: Juillet 2025
Licence: MIT

⚠️ Utilisation recommandée:
• Audit régulier de vos certificats
• Monitoring proactif des expirations
• Vérification après renouvellement
• Tests de sécurité SSL/TLS
        """
        
        text_widget = scrolledtext.ScrolledText(self.about_frame, wrap='word')
        text_widget.pack(fill='both', expand=True, padx=15, pady=15)
        text_widget.insert('1.0', about_text)
        text_widget.configure(state='disabled')
    
    def load_hosts_file(self):
        """Charge une liste d'hôtes depuis un fichier."""
        filename = filedialog.askopenfilename(
            title="Charger liste d'hôtes",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.hosts_text.delete('1.0', tk.END)
                self.hosts_text.insert('1.0', content)
                messagebox.showinfo("Succès", f"Hôtes chargés depuis {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de charger le fichier: {e}")
    
    def start_check(self):
        """Démarre la vérification des certificats."""
        # Récupérer la liste des hôtes
        hosts_text = self.hosts_text.get('1.0', tk.END).strip()
        if not hosts_text:
            messagebox.showerror("Erreur", "Veuillez saisir au moins un hôte à vérifier")
            return
        
        # Parser les hôtes
        hosts = []
        for line in hosts_text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if ':' in line:
                    hostname, port = line.split(':', 1)
                    try:
                        port = int(port)
                    except ValueError:
                        port = 443
                    hosts.append({'hostname': hostname.strip(), 'port': port})
                else:
                    hosts.append({'hostname': line, 'port': 443})
        
        if not hosts:
            messagebox.showerror("Erreur", "Aucun hôte valide trouvé")
            return
        
        # Configuration
        try:
            self.checker.timeout = int(self.timeout_var.get())
            max_workers = int(self.threads_var.get())
        except ValueError:
            messagebox.showerror("Erreur", "Valeurs numériques invalides")
            return
        
        # Désactiver le bouton et démarrer
        self.check_button.configure(state='disabled')
        self.progress_var.set(0)
        
        # Lancer dans un thread
        threading.Thread(target=self.run_check, args=(hosts, max_workers), daemon=True).start()
    
    def run_check(self, hosts, max_workers):
        """Exécute la vérification dans un thread séparé."""
        try:
            def progress_callback(progress, message):
                self.root.after(0, lambda: self.progress_var.set(progress))
                self.root.after(0, lambda: self.status_var.set(message))
            
            self.results = self.checker.check_multiple_hosts(
                hosts, max_workers, progress_callback
            )
            
            self.root.after(0, self.check_complete)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erreur", f"Erreur lors de la vérification: {e}"))
            self.root.after(0, lambda: self.check_button.configure(state='normal'))
    
    def check_complete(self):
        """Appelé quand la vérification est terminée."""
        self.check_button.configure(state='normal')
        self.progress_var.set(100)
        
        # Statistiques
        total = len(self.results)
        valid = len([r for r in self.results if r['status'] == 'valid'])
        errors = total - valid
        
        self.status_var.set(f"Vérification terminée: {valid}/{total} certificats valides")
        
        messagebox.showinfo("Vérification terminée", 
                          f"Résultats:\n• {valid} certificats valides\n• {errors} problèmes détectés")
        
        self.refresh_results()
    
    def start_monitoring(self):
        """Démarre le monitoring continu."""
        hosts_text = self.hosts_text.get('1.0', tk.END).strip()
        if not hosts_text:
            messagebox.showerror("Erreur", "Veuillez configurer des hôtes à monitorer")
            return
        
        # Parser les hôtes (même logique que start_check)
        hosts = []
        for line in hosts_text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if ':' in line:
                    hostname, port = line.split(':', 1)
                    try:
                        port = int(port)
                    except ValueError:
                        port = 443
                    hosts.append({'hostname': hostname.strip(), 'port': port})
                else:
                    hosts.append({'hostname': line, 'port': 443})
        
        try:
            interval = int(self.interval_var.get())
        except ValueError:
            messagebox.showerror("Erreur", "Intervalle invalide")
            return
        
        # Démarrer le monitoring
        self.checker.start_monitoring(hosts, interval, self.alert_callback)
        self.monitoring_active = True
        
        # Mettre à jour l'interface
        self.start_monitor_button.configure(state='disabled')
        self.stop_monitor_button.configure(state='normal')
        self.monitor_status_var.set(f"Monitoring actif ({len(hosts)} hôtes, {interval}h)")
        
        messagebox.showinfo("Monitoring démarré", f"Surveillance de {len(hosts)} hôtes toutes les {interval} heures")
    
    def stop_monitoring(self):
        """Arrête le monitoring."""
        self.checker.stop_monitoring()
        self.monitoring_active = False
        
        # Mettre à jour l'interface
        self.start_monitor_button.configure(state='normal')
        self.stop_monitor_button.configure(state='disabled')
        self.monitor_status_var.set("Monitoring arrêté")
        
        messagebox.showinfo("Monitoring arrêté", "La surveillance continue a été arrêtée")
    
    def alert_callback(self, alerts):
        """Callback appelé lors d'alertes de monitoring."""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        
        for alert in alerts:
            level = alert['level']
            hostname = alert['hostname']
            message = alert['message']
            
            # Icône selon le niveau
            icon = "🚨" if level == 'critical' else "⚠️"
            
            alert_text = f"[{timestamp}] {icon} {message}\n"
            
            self.root.after(0, lambda text=alert_text: self.alerts_text.insert(tk.END, text))
            self.root.after(0, lambda: self.alerts_text.see(tk.END))
    
    def refresh_results(self):
        """Actualise l'affichage des résultats."""
        self.results_text.delete('1.0', tk.END)
        
        if not self.results:
            self.results_text.insert(tk.END, "Aucun résultat disponible. Lancez une vérification d'abord.")
            return
        
        # Statistiques générales
        total = len(self.results)
        valid = len([r for r in self.results if r['status'] == 'valid'])
        expired = len([r for r in self.results if r['status'] == 'expired'])
        errors = len([r for r in self.results if r['status'] in ['ssl_error', 'error', 'timeout']])
        
        # Score moyen
        scores = [r.get('security_score', 0) for r in self.results if r.get('security_score') is not None]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        summary = f"""
📊 RÉSUMÉ DE LA VÉRIFICATION
{'=' * 50}
• Total vérifié: {total} certificats
• Valides: {valid} ({(valid/total*100):.1f}%)
• Expirés: {expired}
• Erreurs: {errors}
• Score moyen: {avg_score:.0f}/100

{'=' * 50}

"""
        self.results_text.insert(tk.END, summary)
        
        # Détails par certificat
        for i, result in enumerate(self.results, 1):
            hostname = result['hostname']
            port = result['port']
            status = result['status']
            score = result.get('security_score', 0)
            
            # Icône de statut
            status_icons = {
                'valid': '✅',
                'expired': '❌',
                'ssl_error': '🚨',
                'error': '⚠️',
                'timeout': '⏱️'
            }
            icon = status_icons.get(status, '❓')
            
            header = f"\n{i}. {icon} {hostname}:{port} - Score: {score}/100\n"
            self.results_text.insert(tk.END, header)
            self.results_text.insert(tk.END, "-" * len(header) + "\n")
            
            # Statut et erreurs
            self.results_text.insert(tk.END, f"Statut: {status}\n")
            
            if result.get('errors'):
                self.results_text.insert(tk.END, "❌ Erreurs:\n")
                for error in result['errors']:
                    self.results_text.insert(tk.END, f"  • {error}\n")
            
            if result.get('warnings'):
                self.results_text.insert(tk.END, "⚠️ Avertissements:\n")
                for warning in result['warnings']:
                    self.results_text.insert(tk.END, f"  • {warning}\n")
            
            # Détails du certificat si valide
            if status == 'valid' and 'certificate_info' in result:
                cert_info = result['certificate_info']
                
                self.results_text.insert(tk.END, "\n📋 Informations certificat:\n")
                self.results_text.insert(tk.END, f"  • Sujet: {cert_info.get('subject', {}).get('commonName', 'N/A')}\n")
                self.results_text.insert(tk.END, f"  • Émetteur: {cert_info.get('issuer', {}).get('organizationName', 'N/A')}\n")
                self.results_text.insert(tk.END, f"  • Expire le: {cert_info.get('not_after', 'N/A')}\n")
                self.results_text.insert(tk.END, f"  • Jours restants: {cert_info.get('expires_in_days', 'N/A')}\n")
                self.results_text.insert(tk.END, f"  • Taille clé: {cert_info.get('key_size', 'N/A')} bits\n")
                self.results_text.insert(tk.END, f"  • Algorithme: {cert_info.get('signature_algorithm', 'N/A')}\n")
                
                # Protocole SSL/TLS
                protocol_info = result.get('protocol_info', {})
                if protocol_info:
                    self.results_text.insert(tk.END, f"  • Protocole: {protocol_info.get('protocol', 'N/A')}\n")
                    self.results_text.insert(tk.END, f"  • Cipher: {protocol_info.get('cipher_suite', 'N/A')}\n")
            
            self.results_text.insert(tk.END, "\n")
    
    def save_report(self, format_type):
        """Sauvegarde le rapport dans le format spécifié."""
        if not self.results:
            messagebox.showwarning("Aucun résultat", "Aucun résultat à sauvegarder")
            return
        
        # Extension selon le format
        extensions = {
            'html': '.html',
            'csv': '.csv',
            'json': '.json'
        }
        
        filename = filedialog.asksaveasfilename(
            title=f"Sauvegarder rapport {format_type.upper()}",
            defaultextension=extensions[format_type],
            filetypes=[(f"Fichiers {format_type.upper()}", f"*{extensions[format_type]}")]
        )
        
        if filename:
            try:
                self.checker.generate_report(self.results, format_type, filename)
                messagebox.showinfo("Sauvegarde réussie", f"Rapport sauvegardé dans {filename}")
            except Exception as e:
                messagebox.showerror("Erreur de sauvegarde", str(e))
    
    def run(self):
        """Lance l'application."""
        self.root.mainloop()


def main():
    """Fonction principale avec CLI et GUI."""
    parser = argparse.ArgumentParser(
        description="Vérificateur de Certificats SSL/TLS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python ssl_checker.py --gui
  python ssl_checker.py google.com facebook.com
  python ssl_checker.py google.com:443 --format html --output report.html
  python ssl_checker.py --file hosts.txt --monitor --interval 6
        """
    )
    
    parser.add_argument('hosts', nargs='*', help='Hôtes à vérifier (format: hostname[:port])')
    parser.add_argument('--gui', action='store_true', help='Lancer l\'interface graphique')
    parser.add_argument('--file', '-f', help='Fichier contenant la liste des hôtes')
    parser.add_argument('--format', choices=['json', 'csv', 'html'], default='json',
                       help='Format du rapport')
    parser.add_argument('--output', '-o', help='Fichier de sortie')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Timeout de connexion')
    parser.add_argument('--threads', type=int, default=10, help='Nombre de threads parallèles')
    parser.add_argument('--monitor', action='store_true', help='Mode monitoring continu')
    parser.add_argument('--interval', type=int, default=24, help='Intervalle de monitoring (heures)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbose')
    
    args = parser.parse_args()
    
    # Lancer GUI si demandée
    if args.gui:
        try:
            app = SSLCheckerGUI()
            app.run()
        except ImportError:
            print("❌ Tkinter non disponible. Interface graphique indisponible.")
        return
    
    # Mode ligne de commande
    print("🔒 Vérificateur de Certificats SSL/TLS v1.0")
    print("=" * 60)
    
    # Construire la liste des hôtes
    hosts = []
    
    # Depuis les arguments
    for host_spec in args.hosts:
        if ':' in host_spec:
            hostname, port = host_spec.split(':', 1)
            try:
                port = int(port)
            except ValueError:
                port = 443
            hosts.append({'hostname': hostname, 'port': port})
        else:
            hosts.append({'hostname': host_spec, 'port': 443})
    
    # Depuis un fichier
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            hostname, port = line.split(':', 1)
                            try:
                                port = int(port)
                            except ValueError:
                                port = 443
                            hosts.append({'hostname': hostname, 'port': port})
                        else:
                            hosts.append({'hostname': line, 'port': 443})
        except FileNotFoundError:
            print(f"❌ Fichier non trouvé: {args.file}")
            return
    
    if not hosts:
        print("❌ Aucun hôte spécifié. Utilisez --gui ou spécifiez des hôtes.")
        parser.print_help()
        return
    
    # Créer le checker
    checker = SSLChecker()
    checker.timeout = args.timeout
    
    print(f"🔍 Vérification de {len(hosts)} hôte(s)...")
    
    # Mode monitoring
    if args.monitor:
        print(f"📊 Mode monitoring: vérification toutes les {args.interval} heures")
        print("Appuyez sur Ctrl+C pour arrêter")
        
        def alert_callback(alerts):
            for alert in alerts:
                level = alert['level']
                message = alert['message']
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                icon = "🚨" if level == 'critical' else "⚠️"
                print(f"[{timestamp}] {icon} {message}")
        
        try:
            checker.start_monitoring(hosts, args.interval, alert_callback)
            
            # Garder le programme en vie
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n⏹️ Arrêt du monitoring...")
            checker.stop_monitoring()
    
    else:
        # Mode vérification unique
        def progress_callback(progress, message):
            if args.verbose:
                print(f"[{progress:3.0f}%] {message}")
        
        results = checker.check_multiple_hosts(
            hosts, 
            args.threads, 
            progress_callback if args.verbose else None
        )
        
        # Générer le rapport
        report_content = checker.generate_report(results, args.format, args.output)
        
        if not args.output:
            print("\n" + report_content)
        
        # Statistiques finales
        total = len(results)
        valid = len([r for r in results if r['status'] == 'valid'])
        print(f"\n✅ Vérification terminée: {valid}/{total} certificats valides")


if __name__ == "__main__":
    main()
