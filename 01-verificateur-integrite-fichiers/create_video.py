import cv2
import numpy as np

def create_demo_video():
    # Configuration
    width, height = 1280, 720
    fps = 1
    duration = 15
    
    # Créer le writer vidéo
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video = cv2.VideoWriter('demo.mp4', fourcc, fps, (width, height))
    
    # Contenu à afficher
    demo_text = [
        "🎬 DÉMONSTRATION: Vérificateur d'Intégrité de Fichiers",
        "",
        "📁 Ajout d'un fichier à la surveillance...",
        "$ python file_integrity_checker.py add test_file.txt",
        "🛡️  Vérificateur d'Intégrité de Fichiers v1.0",
        "✅ Fichier ajouté à la surveillance: test_file.txt",
        "   Hash SHA256: b08ed0aba2049f3313ff18c...",
        "",
        "🔍 Vérification de l'intégrité...",
        "$ python file_integrity_checker.py check-all",
        "🔍 Vérification de 1 fichiers...",
        "✅ test_file.txt: Fichier intact",
        "",
        "📊 Génération d'un rapport...",
        "$ python file_integrity_checker.py report",
        "📄 Rapport généré: integrity_report.txt",
        "",
        "✅ Démonstration terminée!",
        "Le vérificateur surveille l'intégrité des fichiers",
        "avec des hashes SHA256 sécurisés."
    ]
    
    # Générer les frames
    for frame_idx in range(duration * fps):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Calculer les lignes à afficher
        lines_per_second = len(demo_text) / duration
        current_line = int(frame_idx * lines_per_second / fps)
        
        # Afficher les lignes
        y = 50
        for i in range(max(0, current_line-5), min(len(demo_text), current_line+10)):
            line = demo_text[i]
            if line:
                # Couleur selon le type de ligne
                if line.startswith('🎬'):
                    color = (255, 255, 0)  # Cyan pour le titre
                elif line.startswith('$'):
                    color = (0, 255, 0)    # Vert pour les commandes
                elif line.startswith('✅'):
                    color = (0, 255, 0)    # Vert pour les succès
                elif line.startswith('🔍'):
                    color = (255, 255, 0)  # Jaune pour les informations
                else:
                    color = (255, 255, 255)  # Blanc par défaut
                
                cv2.putText(frame, line, (30, y), cv2.FONT_HERSHEY_SIMPLEX, 
                           0.7, color, 2, cv2.LINE_AA)
            y += 30
            if y > height - 50:
                break
        
        video.write(frame)
    
    video.release()
    print("✅ Vidéo démo créée: demo.mp4")

if __name__ == "__main__":
    create_demo_video()
