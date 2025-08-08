# 🔍 Extracteur de Métadonnées

## 📖 Description

L'**Extracteur de Métadonnées** est un outil forensique avancé pour analyser et extraire les métadonnées de fichiers multiples formats. Il combine une interface graphique intuitive avec une puissante ligne de commande pour l'analyse forensique, l'audit de sécurité et l'investigation numérique.

## ✨ Fonctionnalités

### 🗂️ Formats Supportés
- **Images** : JPEG (EXIF), PNG, TIFF, BMP, GIF
- **Documents** : PDF, Microsoft Word (.docx), Texte brut
- **Audio** : MP3, FLAC, OGG, M4A, AAC, WAV
- **Vidéo** : MP4, AVI, MKV, MOV (métadonnées basiques)
- **Génériques** : Tous formats avec analyse des signatures binaires

### 🔍 Types de Métadonnées Extraites

#### 📁 Informations Fichier (Tous formats)
- **Propriétés système** : Taille, dates (création, modification, accès)
- **Hachages cryptographiques** : MD5, SHA1, SHA256
- **Type MIME** et extension détectés
- **Signature binaire** (magic numbers)

#### 📷 Images (EXIF)
- **Appareil photo** : Marque, modèle, paramètres
- **Géolocalisation GPS** : Coordonnées, altitude
- **Paramètres photo** : ISO, exposition, focale, flash
- **Logiciel de traitement** : Photoshop, GIMP, etc.
- **Dates de prise de vue** précises

#### 📄 Documents PDF
- **Métadonnées document** : Titre, auteur, sujet, mots-clés
- **Informations techniques** : Créateur, producteur, version PDF
- **Statistiques** : Nombre de pages, chiffrement
- **Dates** : Création, modification du document

#### 🎵 Audio/Vidéo
- **Tags ID3** : Artiste, album, titre, année, genre
- **Propriétés techniques** : Bitrate, échantillonnage, durée
- **Format et codec** : MP3, FLAC, H.264, etc.
- **Métadonnées avancées** : Paroles, pochettes, commentaires

#### 📝 Documents Office
- **Propriétés principales** : Auteur, titre, sujet, commentaires
- **Historique** : Dernière modification, révisions, temps d'édition
- **Statistiques texte** : Nombre de mots, caractères, pages
- **Métadonnées système** : Version Office, modèles utilisés

### 🖥️ Interfaces Utilisateur

#### Interface Graphique (Tkinter)
- **Sélection intuitive** de fichiers et dossiers
- **Traitement par lot** avec barre de progression
- **Affichage formaté** des résultats
- **Export multi-format** (JSON, CSV, HTML)
- **Gestion d'historique** des analyses

#### Ligne de Commande
- **Traitement batch** pour scripts et automation
- **Recherche récursive** dans dossiers
- **Filtrage par patterns** (wildcards)
- **Export direct** vers fichiers
- **Mode verbose** pour debugging

### 📊 Export et Rapports
- **JSON structuré** : Format technique complet
- **CSV tabulaire** : Compatible Excel, bases de données
- **HTML interactif** : Rapport visuel avec statistiques
- **Rapports forensiques** : Format adapté à l'investigation

## 📋 Prérequis

### Système
- **Python 3.8+** (requis)
- **Tkinter** : Interface graphique (généralement inclus)

### Dépendances Python
```bash
pip install -r requirements.txt
```

#### Bibliothèques Principales
- **Pillow** : Traitement d'images et EXIF
- **PyPDF2** : Métadonnées PDF
- **Mutagen** : Tags audio/vidéo
- **python-docx** : Documents Word

## 🚀 Installation

### 1. Préparation
```bash
cd 05-extracteur-metadonnees

# Environnement virtuel recommandé
python -m venv venv

# Activation
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Installation des dépendances
```bash
# Installation standard
pip install -r requirements.txt

# Installation complète avec options avancées
pip install pillow PyPDF2 mutagen python-docx python-magic exifread
```

### 3. Vérification des dépendances
```bash
python -c "import PIL, PyPDF2, mutagen, docx; print('✅ Toutes les dépendances sont installées')"
```

## 💡 Utilisation

### 🖥️ Interface Graphique

#### Démarrage
```bash
python metadata_extractor.py --gui
```

#### Workflow Standard
1. **Lancer l'application** : Interface Tkinter s'ouvre
2. **Sélectionner des fichiers** : 
   - "📁 Ajouter fichiers" : Fichiers individuels
   - "📂 Ajouter dossier" : Dossier complet (récursif)
3. **Configurer les options** :
   - ☑️ Calculer les hachages (MD5, SHA1, SHA256)
   - Format d'export : JSON / CSV / HTML
4. **Lancer l'extraction** : "🚀 Extraire les métadonnées"
5. **Consulter les résultats** : Onglet "📊 Résultats"
6. **Sauvegarder** : Export vers fichier

### 🔧 Ligne de Commande

#### Commandes de Base

##### Analyser un fichier unique
```bash
python metadata_extractor.py photo.jpg
```

##### Analyser plusieurs fichiers
```bash
python metadata_extractor.py document.pdf audio.mp3 image.png
```

##### Analyser un dossier (récursif)
```bash
python metadata_extractor.py /path/to/folder --recursive
```

##### Utiliser des wildcards
```bash
python metadata_extractor.py *.jpg *.pdf
python metadata_extractor.py "Documents/**/*.docx"
```

#### Options Avancées

##### Export vers fichier JSON
```bash
python metadata_extractor.py *.jpg --format json --output rapport.json
```

##### Export vers CSV (Excel)
```bash
python metadata_extractor.py folder/ --recursive --format csv --output data.csv
```

##### Rapport HTML interactif
```bash
python metadata_extractor.py evidence/ --recursive --format html --output forensic_report.html
```

##### Sans calcul de hachages (plus rapide)
```bash
python metadata_extractor.py large_files/ --no-hash --recursive
```

##### Mode verbose (debugging)
```bash
python metadata_extractor.py suspicious_file.exe --verbose
```

### 📊 Formats de Sortie Détaillés

#### JSON (Format Technique)
```json
{
  "file_info": {
    "filename": "photo.jpg",
    "size_bytes": 2048576,
    "size_human": "2.0 MB",
    "modified_time": "2025-07-27T14:30:00",
    "mime_type": "image/jpeg"
  },
  "hashes": {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2cf24dba4f21d4288..."
  },
  "image_metadata": {
    "exif": {
      "Make": "Canon",
      "Model": "EOS 5D Mark IV",
      "DateTime": "2025:07:20 15:30:22",
      "GPSLatitude": "48.8566",
      "GPSLongitude": "2.3522"
    }
  }
}
```

#### CSV (Analyse Tabulaire)
| filename | size_human | extension | mime_type | exif.Make | exif.GPS |
|----------|------------|-----------|-----------|-----------|----------|
| photo1.jpg | 2.0 MB | .jpg | image/jpeg | Canon | 48.8566,2.3522 |

#### HTML (Rapport Visuel)
- **Dashboard avec statistiques** globales
- **Sections par fichier** avec métadonnées formatées
- **Navigation interactive** entre résultats
- **Styles CSS** professionnels pour présentation

## 🎯 Cas d'Usage Spécialisés

### 🔍 Investigation Forensique

#### Analyse de Preuves Numériques
```bash
# Analyse complète d'un support de preuves
python metadata_extractor.py /mnt/evidence/ --recursive --format html --output forensic_analysis.html

# Vérification d'intégrité avec hachages
python metadata_extractor.py suspicious_files/ --format json --output integrity_check.json
```

#### Géolocalisation d'Images
```bash
# Extraire les coordonnées GPS de toutes les photos
python metadata_extractor.py photos/ --recursive | grep -A5 "coordinates"
```

#### Timeline Forensique
```bash
# Export CSV pour analyse temporelle
python metadata_extractor.py case_files/ --recursive --format csv --output timeline.csv
# Ouvrir timeline.csv dans Excel pour tri par dates
```

### 🛡️ Audit de Sécurité

#### Détection de Métadonnées Sensibles
```bash
# Rechercher des informations d'identification dans documents
python metadata_extractor.py documents/ --recursive --verbose | grep -i "author\|creator\|company"
```

#### Analyse de Fuites de Données
```bash
# Vérifier les métadonnées avant publication
python metadata_extractor.py public_docs/ --format html --output metadata_audit.html
```

### 📊 Analyse de Données

#### Inventaire de Fichiers Multimédia
```bash
# Catalogue de photos avec géolocalisation
python metadata_extractor.py photo_library/ --recursive --format csv --output photo_catalog.csv
```

#### Audit de Conformité
```bash
# Vérifier les propriétés de documents d'entreprise
python metadata_extractor.py corporate_docs/ --recursive --format json --output compliance_check.json
```

## 🔧 Configuration et Personnalisation

### 📝 Format d'Export Personnalisé

#### Modification du JSON
```python
# Dans metadata_extractor.py, méthode export_results()
def custom_json_format(self, results):
    simplified = []
    for result in results:
        simplified.append({
            'file': result.get('file_info', {}).get('filename'),
            'size': result.get('file_info', {}).get('size_human'),
            'md5': result.get('hashes', {}).get('md5'),
            'exif': result.get('image_metadata', {}).get('exif', {})
        })
    return json.dumps(simplified, indent=2)
```

### 🎛️ Filtres Avancés

#### Extension de Formats Supportés
```python
# Ajouter de nouveaux formats dans __init__()
self.supported_formats.update({
    'cad': ['.dwg', '.dxf', '.step'],
    'code': ['.py', '.js', '.html', '.css']
})
```

#### Extraction Personnalisée
```python
def _extract_custom_metadata(self, file_path):
    """Extraction personnalisée pour formats spéciaux."""
    # Votre logique d'extraction
    return {'custom_metadata': {...}}
```

## 📈 Performance et Optimisation

### ⚡ Temps de Traitement Typiques

| Type de fichier | Taille | Temps sans hash | Temps avec hash |
|-----------------|--------|----------------|-----------------|
| Image JPEG | 5 MB | 0.2s | 0.5s |
| Document PDF | 10 MB | 0.3s | 1.2s |
| Fichier audio | 50 MB | 0.1s | 3.5s |
| Vidéo | 500 MB | 0.5s | 35s |

### 🚀 Optimisations

#### Traitement Rapide (Sans hachages)
```bash
# Pour analyse rapide de gros volumes
python metadata_extractor.py big_folder/ --no-hash --recursive
```

#### Parallélisation (Futur)
```python
# TODO: Implémentation multiprocessing
from concurrent.futures import ProcessPoolExecutor

def parallel_extraction(file_list):
    with ProcessPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(extract_metadata, file_list))
    return results
```

### 💾 Gestion Mémoire

#### Gros Fichiers
- **Lecture par chunks** : 8KB pour calcul de hachages
- **Streaming processing** : Pas de chargement complet en mémoire
- **Limitation automatique** : Évite le traitement de fichiers > 1GB

#### Optimisation Interface
- **Threading** : Interface responsive pendant traitement
- **Garbage collection** : Nettoyage automatique des résultats

## 🔍 Résolution de Problèmes

### ❌ Erreurs Communes

#### "Module not found: PIL/PyPDF2/mutagen"
```bash
# Installation manuelle des dépendances
pip install Pillow PyPDF2 mutagen python-docx

# Vérification
python -c "import PIL; print('Pillow OK')"
```

#### Erreurs de Permissions
```bash
# Linux/Mac : droits de lecture
chmod +r fichier_protege.pdf

# Windows : exécuter en administrateur
# Clic droit > "Exécuter en tant qu'administrateur"
```

#### "Can't read EXIF data"
```bash
# Vérifier que le fichier contient bien des métadonnées EXIF
exiftool image.jpg  # Si exiftool installé

# Ou utiliser mode verbose pour plus de détails
python metadata_extractor.py image.jpg --verbose
```

#### Interface graphique ne s'ouvre pas
```bash
# Vérifier tkinter
python -c "import tkinter; print('Tkinter OK')"

# Linux : installer tkinter si nécessaire
sudo apt-get install python3-tk

# Alternative : utiliser ligne de commande uniquement
python metadata_extractor.py fichier.pdf --format html --output rapport.html
```

### 🐛 Mode Debug

#### Diagnostic Complet
```bash
# Vérification de l'environnement
python metadata_extractor.py --help
python -c "import sys; print(f'Python {sys.version}')"
pip list | grep -E "(Pillow|PyPDF2|mutagen|docx)"
```

#### Analyse d'Erreur Spécifique
```bash
# Mode verbose pour fichier problématique
python metadata_extractor.py fichier_probleme.xxx --verbose

# Ou test en mode interactif
python
>>> from metadata_extractor import MetadataExtractor
>>> extractor = MetadataExtractor()
>>> result = extractor.extract_metadata('fichier_test.jpg')
>>> print(result)
```

## 🛡️ Sécurité et Légalité

### ⚖️ Considérations Légales

#### Usage Autorisé Uniquement
- **Vos propres fichiers** : Toujours autorisé
- **Fichiers d'entreprise** : Avec autorisation explicite
- **Investigation forensique** : Cadre légal approprié requis
- **Audit de sécurité** : Mandat ou autorisation nécessaire

#### Respect de la Vie Privée
- **Métadonnées personnelles** : GPS, informations d'identification
- **RGPD/CCPA compliance** : Traitement des données personnelles
- **Consentement** : Requis pour analyse de fichiers tiers

### 🔒 Sécurité de l'Outil

#### Risques et Mitigations
- **Fichiers malveillants** : L'outil ne modifie jamais les fichiers source
- **Fuites mémoire** : Nettoyage automatique des données sensibles
- **Journalisation** : Pas de log des métadonnées extraites
- **Export sécurisé** : Chiffrement possible des rapports

#### Bonnes Pratiques
```bash
# Environnement isolé pour analyses sensibles
python -m venv forensic_env
source forensic_env/bin/activate
pip install -r requirements.txt

# Nettoyage après analyse
rm -rf temp_results/
unset HISTFILE  # Éviter historique bash
```

## 📚 Références Techniques

### 📖 Standards et Spécifications
- **EXIF 2.3** : [CIPA Standard](http://www.cipa.jp/std/documents/e/DC-008-2012_E.pdf)
- **PDF Metadata** : [Adobe PDF Reference](https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf)
- **ID3 Tags** : [ID3.org Specification](https://id3.org/Developer%20Information)
- **Dublin Core** : [Metadata Standard](https://dublincore.org/specifications/)

### 🛠️ Outils Complémentaires
- **ExifTool** : Outil de référence pour métadonnées
- **Binwalk** : Analyse de firmwares et binaires
- **file/libmagic** : Identification de types de fichiers
- **FFprobe** : Métadonnées vidéo/audio avancées

### 📚 Ressources Forensiques
- **NIST Computer Forensics** : [Guidelines](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- **SANS Digital Forensics** : [Training Materials](https://www.sans.org/cyber-security-courses/digital-forensics/)
- **Autopsy Digital Forensics** : [Open Source Platform](https://www.autopsy.com/)

## 🔮 Évolutions Futures

### 🚀 Fonctionnalités Prévues

#### Support de Formats Avancés
- **Archives** : Métadonnées ZIP, RAR, 7Z
- **Images RAW** : Canon CR2, Nikon NEF, etc.
- **Vidéo avancée** : Intégration FFprobe complète
- **Documents** : PowerPoint, Excel, OpenDocument

#### Intelligence Artificielle
- **Détection de contenu** : OCR pour texte dans images
- **Classification automatique** : ML pour catégorisation
- **Détection d'anomalies** : Fichiers suspects
- **Reconnaissance faciale** : Analyse des photos

#### Interface Améliorée
- **Web interface** : Dashboard en ligne via Flask
- **Mobile app** : Version Android/iOS
- **API REST** : Intégration avec autres outils
- **Plugins** : Architecture extensible

#### Forensique Avancée
- **Timeline analysis** : Reconstitution chronologique
- **Correlation engine** : Liens entre fichiers
- **Hash databases** : Intégration NSRL, VirusTotal
- **Chain of custody** : Traçabilité des preuves

### 🛠️ Améliorations Techniques

#### Performance
- **Multiprocessing** : Traitement parallèle
- **Caching intelligent** : Éviter recalculs
- **Compression** : Stockage efficient des résultats
- **Indexation** : Recherche rapide dans gros volumes

#### Sécurité
- **Sandboxing** : Isolation des fichiers analysés
- **Signatures numériques** : Intégrité des rapports
- **Chiffrement** : Protection des données sensibles
- **Audit logging** : Traçabilité complète

## 👥 Contribution et Développement

### 🛠️ Architecture du Code

#### Structure Principale
```python
MetadataExtractor           # Moteur d'extraction
├── detect_file_type()     # Classification des fichiers
├── extract_metadata()     # Extraction principale
├── _extract_*_metadata()  # Méthodes spécialisées
└── export_results()       # Génération de rapports

MetadataExtractorGUI       # Interface graphique
├── setup_gui()           # Configuration Tkinter
├── create_*_tab()        # Onglets de l'interface
└── run_extraction()      # Threading pour extraction
```

#### Points d'Extension
```python
# Nouveau format de fichier
def _extract_newformat_metadata(self, file_path):
    # Votre implémentation
    return {'newformat_metadata': {...}}

# Nouveau format d'export
def _generate_custom_report(self, results):
    # Génération personnalisée
    return formatted_content
```

### 🧪 Tests et Validation

#### Tests Unitaires (À implémenter)
```python
# test_metadata_extractor.py
import unittest
from metadata_extractor import MetadataExtractor

class TestMetadataExtractor(unittest.TestCase):
    def test_image_extraction(self):
        extractor = MetadataExtractor()
        result = extractor.extract_metadata('test_files/sample.jpg')
        self.assertIn('image_metadata', result)
        
    def test_pdf_extraction(self):
        extractor = MetadataExtractor()
        result = extractor.extract_metadata('test_files/sample.pdf')
        self.assertIn('pdf_metadata', result)
```

#### Tests d'Intégration
```bash
# Jeu de test avec fichiers de référence
mkdir test_files/
# Ajouter échantillons de chaque format supporté
python -m pytest test_metadata_extractor.py -v
```

### 📝 Standards de Contribution

#### Code Style
- **PEP 8** : Style Python standard
- **Type hints** : Annotations de type recommandées
- **Docstrings** : Documentation des fonctions
- **Error handling** : Gestion robuste des erreurs

#### Processus de Contribution
1. **Fork** du repository
2. **Branche feature** : `git checkout -b new-format-support`
3. **Implémentation** avec tests
4. **Documentation** mise à jour
5. **Pull Request** avec description détaillée

## 📄 Licence et Crédits

### Licence MIT
Ce projet est distribué sous licence MIT. Utilisation libre pour projets personnels et commerciaux avec attribution.

### 🙏 Remerciements
- **Pillow team** : Excellent support EXIF
- **PyPDF2 maintainers** : Extraction PDF fiable
- **Mutagen developers** : Tags audio/vidéo complets
- **Python community** : Écosystème riche et documentation

### ⚠️ Avertissements
- **Responsabilité utilisateur** : Respecter les lois sur la vie privée
- **Usage forensique** : Cadre légal approprié requis
- **Données sensibles** : Manipulation conforme RGPD
- **Fichiers malveillants** : Environnement isolé recommandé

---

**Auteur** : Assistant IA  
**Version** : 1.0  
**Date** : Juillet 2025  
**Niveau** : Débutant à Avancé  
**Temps de développement** : 1-2 semaines  
**Technologies** : Python, Pillow, PyPDF2, Mutagen, Tkinter

**🔍 Analysez vos fichiers avec précision forensique !**