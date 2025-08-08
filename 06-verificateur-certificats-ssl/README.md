# 🔒 Vérificateur de Certificats SSL/TLS

## 📖 Description

Le **Vérificateur de Certificats SSL/TLS** est un outil professionnel pour auditer la sécurité des certificats SSL/TLS. Il combine vérification ponctuelle, monitoring continu et analyse de sécurité avancée dans une interface moderne et intuitive.

## ✨ Fonctionnalités

### 🔍 Vérification Complète
- **Validité des certificats** : Dates, signature, chaîne de confiance
- **Analyse de sécurité** : Algorithmes, taille des clés, protocoles
- **Détection d'expiration** : Alertes 7, 30, 90 jours avant expiration
- **Vérification de nom d'hôte** : Correspondance avec SAN et CN
- **Chaîne de certification** : Validation complète jusqu'à la racine

### 🌐 Support Multi-Protocole
- **HTTPS** (port 443) : Sites web et APIs
- **SMTPS** (port 465, 587) : Serveurs mail sécurisés
- **IMAPS/POP3S** (ports 993, 995) : Messagerie sécurisée
- **LDAPS** (port 636) : Annuaires sécurisés
- **Ports personnalisés** : Configuration flexible

### 📊 Monitoring Automatique
- **Surveillance continue** : Vérifications programmables
- **Alertes intelligentes** : Notifications critiques et avertissements
- **Historique complet** : Suivi des changements dans le temps
- **Planification flexible** : Intervalles configurables

### 🎯 Analyse de Sécurité
- **Score de sécurité** : Note de 0 à 100 points
- **Détection d'algorithmes faibles** : MD5, SHA1, DES, 3DES, RC4
- **Recommandations** : Conseils d'amélioration personnalisés
- **Conformité standards** : Vérification contre les meilleures pratiques

### 📋 Rapports Professionnels
- **HTML interactif** : Dashboard avec graphiques et statistiques
- **CSV détaillé** : Export pour analyse Excel/bases de données
- **JSON structuré** : Intégration avec APIs et outils tiers
- **Impression** : Rapports prêts pour audit et conformité

### 🖥️ Double Interface
- **Interface graphique** : Application Tkinter moderne et intuitive
- **Ligne de commande** : Automation et intégration scripts
- **Traitement par lot** : Vérification de centaines d'hôtes simultanément
- **Mode serveur** : Monitoring continu en arrière-plan

## 📋 Prérequis

### Système
- **Python 3.8+** (requis)
- **Connexion réseau** : Accès aux serveurs à vérifier
- **Certificats racine** : CA bundle système à jour

### Dépendances Python
```bash
pip install -r requirements.txt
```

#### Bibliothèques Principales
- **cryptography** : Analyse des certificats X.509
- **requests** : Tests de connectivité SSL
- **schedule** : Monitoring automatique programmable

## 🚀 Installation

### 1. Téléchargement et Préparation
```bash
cd 06-verificateur-certificats-ssl

# Environnement virtuel (recommandé)
python -m venv venv

# Activation
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Installation des Dépendances
```bash
# Installation standard
pip install -r requirements.txt

# Vérification
python -c "import ssl, cryptography, requests, schedule; print('✅ Installation réussie')"
```

### 3. Test de Fonctionnement
```bash
# Test rapide en ligne de commande
python ssl_checker.py google.com

# Test interface graphique
python ssl_checker.py --gui
```

## 💡 Utilisation

### 🖥️ Interface Graphique

#### Démarrage
```bash
python ssl_checker.py --gui
```

#### Workflow Standard
1. **Onglet "🔍 Vérification"**
   - Saisir les hôtes à vérifier (un par ligne)
   - Format : `hostname` ou `hostname:port`
   - Configurer timeout et nombre de threads
   - Cliquer "🚀 Vérifier les certificats"

2. **Onglet "📊 Monitoring"**
   - Configurer l'intervalle de surveillance
   - Démarrer le monitoring continu
   - Consulter les alertes en temps réel

3. **Onglet "📋 Résultats"**
   - Analyser les résultats détaillés
   - Sauvegarder les rapports HTML/CSV
   - Consulter l'historique des vérifications

### 🔧 Ligne de Commande

#### Commandes de Base

##### Vérification Simple
```bash
# Un seul hôte
python ssl_checker.py google.com

# Plusieurs hôtes
python ssl_checker.py google.com facebook.com github.com

# Avec port personnalisé
python ssl_checker.py mail.google.com:993
```

##### Vérification depuis Fichier
```bash
# Créer un fichier hosts.txt
echo -e "google.com\nfacebook.com:443\ngithub.com" > hosts.txt

# Vérifier depuis le fichier
python ssl_checker.py --file hosts.txt
```

##### Options de Performance
```bash
# Timeout personnalisé et plus de threads
python ssl_checker.py --file hosts.txt --timeout 5 --threads 20

# Mode verbose pour debugging
python ssl_checker.py google.com --verbose
```

#### Génération de Rapports

##### Rapport HTML Interactif
```bash
python ssl_checker.py google.com facebook.com --format html --output audit_ssl.html
```

##### Export CSV pour Excel
```bash
python ssl_checker.py --file enterprise_hosts.txt --format csv --output certificates_audit.csv
```

##### Données JSON pour APIs
```bash
python ssl_checker.py google.com --format json --output cert_data.json
```

#### Monitoring Continu

##### Surveillance 24h/24
```bash
# Monitoring toutes les 6 heures
python ssl_checker.py --file production_hosts.txt --monitor --interval 6

# Avec logging verbose
python ssl_checker.py --file hosts.txt --monitor --interval 24 --verbose
```

### 📊 Interprétation des Résultats

#### Scores de Sécurité
- **90-100** : Excellente sécurité 🟢
- **75-89** : Bonne sécurité 🟡  
- **60-74** : Sécurité acceptable 🟠
- **< 60** : Sécurité insuffisante 🔴

#### États des Certificats
- **✅ Valid** : Certificat valide et sécurisé
- **❌ Expired** : Certificat expiré
- **🚨 SSL Error** : Erreur de configuration SSL
- **⚠️ Warning** : Problèmes mineurs détectés
- **⏱️ Timeout** : Serveur inaccessible

#### Alertes Communes
- **Expiration prochaine** : Renouvellement nécessaire
- **Algorithme faible** : Mise à jour de configuration requise
- **Nom d'hôte incorrect** : Certificat ne correspond pas au domaine
- **Chaîne incomplète** : Certificats intermédiaires manquants
- **Protocole obsolète** : Mise à jour SSL/TLS requise

## 🎯 Cas d'Usage Professionnels

### 🏢 Audit d'Entreprise

#### Vérification de l'Infrastructure
```bash
# Sites web publics
echo -e "www.entreprise.com\napi.entreprise.com\nshop.entreprise.com" > public_sites.txt
python ssl_checker.py --file public_sites.txt --format html --output audit_public.html

# Services internes (VPN requis)
echo -e "intranet.entreprise.local:443\nmail.entreprise.local:993" > internal_services.txt
python ssl_checker.py --file internal_services.txt --format csv --output audit_internal.csv
```

#### Monitoring de Production
```bash
# Surveillance continue des services critiques
python ssl_checker.py --file critical_services.txt --monitor --interval 1 > monitoring.log 2>&1 &
```

### 🔒 Audit de Sécurité

#### Évaluation de Conformité
```bash
# Vérification selon standards de sécurité
python ssl_checker.py --file all_services.txt --format json --output security_compliance.json

# Analyse des résultats avec jq
cat security_compliance.json | jq '.[] | select(.security_score < 80) | {hostname, score: .security_score, issues: .warnings}'
```

#### Tests de Pénétration
```bash
# Identification des vulnérabilités SSL
python ssl_checker.py target.company.com --verbose | grep -E "(weak|obsolete|deprecated)"
```

### 🌐 Gestion de Certificats

#### Planification des Renouvellements
```bash
# Export CSV pour suivi des expirations
python ssl_checker.py --file all_certificates.txt --format csv --output expiration_tracking.csv

# Filtrage des certificats expirant bientôt (bash)
python ssl_checker.py --file hosts.txt --format json | jq '.[] | select(.certificate_info.expires_in_days < 30)'
```

#### Validation Post-Renouvellement
```bash
# Vérification après renouvellement
python ssl_checker.py renewed-cert.domain.com --verbose

# Comparaison avant/après
python ssl_checker.py domain.com --format json --output before_renewal.json
# ... renouvellement ...
python ssl_checker.py domain.com --format json --output after_renewal.json
```

## 🛠️ Configuration Avancée

### 📝 Fichier d'Hôtes Format Étendu

#### hosts.txt Exemple
```text
# Sites web principaux
google.com
facebook.com:443
github.com

# Services mail
smtp.gmail.com:587
imap.gmail.com:993

# Services internes  
# internal.company.com:8443

# APIs externes
api.service.com
webhook.provider.com:443
```

### ⚙️ Personnalisation des Paramètres

#### Configuration dans le Code
```python
# Dans ssl_checker.py, classe SSLChecker.__init__()
self.timeout = 15              # Timeout plus long
self.min_key_size = 4096       # Exiger des clés plus fortes
self.recommended_protocols = ['TLSv1.3']  # Seulement TLS 1.3
```

#### Variables d'Environnement
```bash
# Configuration via environnement
export SSL_TIMEOUT=20
export SSL_MIN_KEY_SIZE=4096
export SSL_THREADS=50

python ssl_checker.py --file hosts.txt
```

### 📧 Notifications Personnalisées

#### Intégration Email (Extension)
```python
import smtplib
from email.mime.text import MIMEText

def send_alert_email(alerts):
    for alert in alerts:
        if alert['level'] == 'critical':
            msg = MIMEText(f"Alerte SSL: {alert['message']}")
            msg['Subject'] = f"SSL Alert: {alert['hostname']}"
            msg['From'] = 'ssl-monitor@company.com'
            msg['To'] = 'admin@company.com'
            
            server = smtplib.SMTP('localhost')
            server.send_message(msg)
            server.quit()
```

### 🔧 Intégration avec Autres Outils

#### Nagios/Icinga
```bash
#!/bin/bash
# check_ssl_certificates.sh
result=$(python ssl_checker.py --file $1 --format json)
critical=$(echo "$result" | jq '.[] | select(.status != "valid") | length')

if [ "$critical" -gt 0 ]; then
    echo "CRITICAL: $critical certificat(s) en erreur"
    exit 2
else
    echo "OK: Tous les certificats sont valides"
    exit 0
fi
```

#### Prometheus/Grafana
```python
# Exposition de métriques Prometheus
from prometheus_client import Gauge, start_http_server

cert_expiry_days = Gauge('ssl_cert_expiry_days', 'Days until certificate expiry', ['hostname'])
cert_score = Gauge('ssl_cert_security_score', 'Certificate security score', ['hostname'])

def update_metrics(results):
    for result in results:
        hostname = result['hostname']
        if result['status'] == 'valid':
            cert_info = result.get('certificate_info', {})
            expiry_days = cert_info.get('expires_in_days', 0)
            security_score = result.get('security_score', 0)
            
            cert_expiry_days.labels(hostname=hostname).set(expiry_days)
            cert_score.labels(hostname=hostname).set(security_score)

# Démarrer le serveur de métriques
start_http_server(8000)
```

## 📊 Analyse et Reporting

### 📈 Tableau de Bord HTML

Le rapport HTML généré inclut :

#### 📋 Vue d'Ensemble
- **Statistiques globales** : Total, valides, expirés, erreurs
- **Score moyen** de sécurité
- **Graphiques visuels** des répartitions
- **Tendances temporelles** (si historique disponible)

#### 🔍 Détails par Certificat
- **Informations générales** : Sujet, émetteur, validité
- **Analyse technique** : Algorithmes, taille de clé, protocoles
- **Évaluation de sécurité** : Points forts et faibles
- **Recommandations** : Actions d'amélioration spécifiques

#### 🚨 Alertes et Priorités
- **Critique** : Action immédiate requise
- **Avertissement** : Planification nécessaire  
- **Information** : Bonnes pratiques

### 📊 Export CSV Détaillé

Colonnes principales du CSV :
- `Hostname`, `Port`, `Status`, `Security_Score`
- `Expires_In_Days`, `Issuer`, `Key_Size`, `Protocol`
- `Checked_At`, `Errors`, `Warnings`

#### Analyse Excel
```excel
=COUNTIF(D:D,"<60")           // Certificats score < 60
=AVERAGEIF(C:C,"valid",D:D)   // Score moyen des certificats valides  
=COUNTIF(E:E,"<30")           // Certificats expirant dans 30 jours
```

### 📈 Métriques de Performance

#### Temps de Vérification Typiques
| Nombre d'hôtes | Threads | Temps approximatif |
|----------------|---------|-------------------|
| 10 | 10 | 5-10 secondes |
| 50 | 20 | 15-30 secondes |
| 100 | 30 | 30-60 secondes |
| 500 | 50 | 3-5 minutes |

#### Optimisation Performance
```bash
# Pour de gros volumes
python ssl_checker.py --file large_hosts.txt --threads 50 --timeout 5

# Pour précision maximale
python ssl_checker.py --file critical_hosts.txt --threads 5 --timeout 30
```

## 🔍 Résolution de Problèmes

### ❌ Erreurs Communes

#### "SSL: CERTIFICATE_VERIFY_FAILED"
```bash
# Mise à jour des certificats racine
# macOS:
/Applications/Python\ 3.x/Install\ Certificates.command

# Linux:
sudo apt-get update && sudo apt-get install ca-certificates

# Windows: Généralement automatique
```

#### "TimeoutError" / Connexions lentes
```bash
# Augmenter le timeout
python ssl_checker.py slow-server.com --timeout 30

# Réduire les threads pour connexions instables
python ssl_checker.py --file hosts.txt --threads 5
```

#### "Name or service not known"
```bash
# Vérifier la résolution DNS
nslookup problematic-host.com

# Utiliser IP directement si nécessaire
python ssl_checker.py 8.8.8.8:443
```

#### Interface graphique ne démarre pas
```bash
# Vérifier tkinter
python -c "import tkinter; print('Tkinter disponible')"

# Installation sur Linux si nécessaire
sudo apt-get install python3-tk

# Alternative: utiliser CLI uniquement
python ssl_checker.py --help
```

### 🐛 Mode Debug

#### Diagnostic Approfondi
```bash
# Maximum de verbosité
python ssl_checker.py problematic-host.com --verbose --timeout 30

# Test de connectivité basique
python -c "import socket; socket.create_connection(('hostname', 443), timeout=10)"

# Vérification manuelle avec OpenSSL
openssl s_client -connect hostname:443 -servername hostname
```

#### Analyse des Erreurs SSL
```python
# Test interactif Python
import ssl
import socket

hostname = 'problematic-host.com'
context = ssl.create_default_context()

try:
    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print("Connexion SSL réussie")
            print("Protocole:", ssock.version())
            print("Cipher:", ssock.cipher())
except Exception as e:
    print(f"Erreur SSL: {e}")
```

## 🛡️ Sécurité et Conformité

### 🔒 Bonnes Pratiques SSL/TLS

#### Configuration Serveur Recommandée
- **Protocoles** : TLS 1.2 minimum, TLS 1.3 préféré
- **Clés RSA** : 2048 bits minimum, 4096 bits recommandé
- **Clés ECDSA** : P-256 minimum, P-384 recommandé
- **Algorithmes hash** : SHA-256 minimum
- **Perfect Forward Secrecy** : Activé (ECDHE)

#### Cipher Suites Recommandés
```
TLS_AES_256_GCM_SHA384 (TLS 1.3)
TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
TLS_AES_128_GCM_SHA256 (TLS 1.3)
ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2)
ECDHE-RSA-CHACHA20-POLY1305 (TLS 1.2)
```

### ⚖️ Conformité Réglementaire

#### Standards Supportés
- **PCI DSS** : Exigences SSL/TLS pour paiements
- **HIPAA** : Chiffrement des données de santé
- **SOX** : Sécurité des systèmes financiers
- **GDPR** : Protection des données personnelles

#### Audit et Documentation
```bash
# Rapport de conformité PCI DSS
python ssl_checker.py --file pci_systems.txt --format html --output pci_compliance.html

# Export pour audit SOX
python ssl_checker.py --file financial_systems.txt --format csv --output sox_audit.csv
```

### 🔐 Gestion des Certificats

#### Cycle de Vie des Certificats
1. **Génération** : Clés et CSR sécurisés
2. **Émission** : CA de confiance
3. **Déploiement** : Configuration serveur
4. **Monitoring** : Surveillance continue
5. **Renouvellement** : Avant expiration
6. **Révocation** : Si compromis

#### Recommandations de Renouvellement
- **Certificats publics** : 90 jours avant expiration
- **Certificats internes** : 30-60 jours selon criticité
- **Certificats wildcard** : 45 jours minimum
- **Certificats code signing** : 6 mois avant expiration

## 📚 Références Techniques

### 📖 Standards et RFCs
- **RFC 5280** : Internet X.509 Public Key Infrastructure
- **RFC 8446** : Transport Layer Security (TLS) Version 1.3
- **RFC 7525** : Recommendations for Secure Use of TLS
- **RFC 6066** : Transport Layer Security Extensions

### 🛠️ Outils Complémentaires
- **OpenSSL** : Toolkit SSL/TLS de référence
- **SSLyze** : Scanner SSL/TLS avancé
- **testssl.sh** : Script de test SSL complet
- **SSL Labs** : Test en ligne de qualité SSL

### 🔗 Ressources Utiles
- **Mozilla SSL Configuration Generator** : Configuration optimale
- **OWASP Transport Layer Security** : Guide de sécurité
- **NIST SP 800-52** : Guidelines for SSL/TLS
- **CIS Controls** : Contrôles de sécurité SSL/TLS

## 🔮 Évolutions Futures

### 🚀 Fonctionnalités Prévues

#### Améliorations Techniques
- **Support IPv6** : Vérification sur réseaux IPv6
- **DANE/TLSA** : Validation DNS-based Authentication
- **Certificate Transparency** : Vérification CT logs
- **HPKP** : HTTP Public Key Pinning
- **HSTS** : HTTP Strict Transport Security

#### Interface Utilisateur
- **Interface web** : Dashboard accessible par navigateur
- **API REST** : Intégration programmatique complète
- **Mobile app** : Version Android/iOS
- **Intégration cloud** : AWS, Azure, GCP

#### Intelligence Artificielle
- **Prédiction d'expiration** : ML pour anticipation
- **Détection d'anomalies** : Changements suspects
- **Optimisation automatique** : Suggestions personnalisées
- **Analyse de tendances** : Évolution de la sécurité

### 🛠️ Améliorations Techniques

#### Performance
- **Async/await** : Programmation asynchrone
- **Cache intelligent** : Éviter vérifications redondantes
- **Load balancing** : Distribution des vérifications
- **CDN awareness** : Gestion des certificats CDN

#### Intégrations
- **Docker containers** : Déploiement containerisé
- **Kubernetes** : Orchestration et scaling
- **CI/CD pipelines** : Intégration DevOps
- **Infrastructure as Code** : Terraform, Ansible

## 👥 Contribution et Support

### 🛠️ Architecture Technique

#### Structure du Code
```python
SSLChecker                  # Moteur principal
├── check_certificate()    # Vérification individuelle
├── check_multiple_hosts() # Vérification en lot
├── start_monitoring()     # Surveillance continue
└── generate_report()      # Génération de rapports

SSLCheckerGUI              # Interface graphique
├── create_check_tab()     # Onglet vérification
├── create_monitor_tab()   # Onglet monitoring
└── create_results_tab()   # Onglet résultats
```

#### Points d'Extension
```python
# Nouveau format de rapport
def _generate_xml_report(self, results):
    # Implémentation XML
    return xml_content

# Nouveau type d'alerte
def custom_alert_handler(self, alerts):
    # Intégration Slack, Teams, etc.
    pass

# Nouvelle métrique de sécurité
def _check_custom_vulnerability(self, cert_obj):
    # Vérification spécifique
    return analysis_result
```

### 📝 Standards de Développement

#### Code Quality
- **PEP 8** : Style Python standard
- **Type hints** : Annotations complètes
- **Docstrings** : Documentation détaillée
- **Unit tests** : Couverture > 80%
- **Code review** : Validation par pairs

#### Sécurité
- **Input validation** : Sanitisation des entrées
- **Error handling** : Gestion robuste des erreurs
- **Secure defaults** : Configuration sécurisée par défaut
- **Audit logs** : Traçabilité des opérations

## 📄 Licence et Mentions Légales

### Licence MIT
Ce projet est distribué sous licence MIT. Utilisation libre avec attribution.

### ⚠️ Avertissements Légaux
- **Utilisation autorisée uniquement** : Vos systèmes ou avec permission
- **Respect des lois locales** : Conformité réglementaire
- **Pas de garantie** : Outil fourni "en l'état"
- **Responsabilité utilisateur** : Validation des configurations

### 🙏 Remerciements
- **OpenSSL team** : Fondation SSL/TLS
- **cryptography.io** : Bibliothèque Python excellente
- **Python community** : Écosystème riche
- **Security researchers** : Découverte des vulnérabilités

---

**Auteur** : Assistant IA  
**Version** : 1.0  
**Date** : Juillet 2025  
**Niveau** : Intermédiaire à Avancé  
**Temps de développement** : 1-2 semaines  
**Technologies** : Python, SSL/TLS, Cryptography, Tkinter

**🔒 Sécurisez votre infrastructure SSL/TLS avec confiance !**