#!/bin/bash
clear
echo "🎬 === DÉMONSTRATION: Vérificateur d'Intégrité de Fichiers ==="
echo
echo "📁 Contenu du répertoire:"
ls -la
echo
echo "💾 Ajout d'un fichier à la surveillance..."
python file_integrity_checker.py add test_file.txt
echo
echo "🔍 Vérification de l'intégrité..."
python file_integrity_checker.py check-all
echo
echo "📋 Liste des fichiers surveillés..."
python file_integrity_checker.py list
echo
echo "📊 Génération d'un rapport..."
python file_integrity_checker.py report
echo
echo "✅ Démonstration terminée!"
echo "📄 Contenu du rapport généré:"
echo "----------------------------------------"
head -n 15 integrity_report.txt
