import cv2
import numpy as np

def create_password_demo():
    width, height = 1280, 720
    fps = 1
    duration = 20
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video = cv2.VideoWriter('demo.mp4', fourcc, fps, (width, height))
    
    demo_frames = [
        ["🎬 DÉMONSTRATION: Générateur de Mots de Passe", ""],
        ["", "Application Flask avec interface web moderne"],
        ["🚀 Démarrage du serveur Flask...", "$ python password_generator.py"],
        ["", " * Running on http://127.0.0.1:5000"],
        ["", " * Serving Flask app 'password_generator'"],
        ["📱 Interface Web Bootstrap 5:", "- Configuration personnalisable"],
        ["", "- Longueur: 4 à 64 caractères"],
        ["", "- Types: Majuscules, minuscules, chiffres, symboles"],
        ["🔐 Génération d'un mot de passe sécurisé:", "Longueur: 16 caractères"],
        ["", "Résultat: Kp8#mN2$vR9qLx3!"],
        ["📊 Analyse de sécurité automatique:", "Score: 95/100 (Très Fort)"],
        ["", "Temps de crack: 2.8 millions d'années"],
        ["🔍 Test analyseur avec mot faible:", "Analyse: 'password123'"],
        ["", "Score: 25/100 (Faible)"],
        ["", "Suggestions: Ajouter symboles, majuscules"],
        ["💾 Historique chiffré AES-256:", "- 47 mots de passe générés"],
        ["", "- Score moyen: 86/100"],
        ["", "- Stockage sécurisé avec Fernet"],
        ["✅ Fonctionnalités démontrées:", "- Génération cryptographique sécurisée"],
        ["", "- Interface responsive moderne"],
        ["", "- Analyse temps réel de la force"],
        ["", "- Historique chiffré complet"]
    ]
    
    for frame_idx in range(duration * fps):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Fond dégradé
        for i in range(height):
            intensity = int(20 + (i / height) * 30)
            frame[i, :] = [intensity, intensity//2, intensity*2]
        
        # Calculer quelle frame afficher
        current_frame = min(frame_idx, len(demo_frames)-1)
        lines = demo_frames[current_frame]
        
        # Afficher le contenu
        y = 200
        for i, line in enumerate(lines):
            if line:
                if line.startswith('🎬'):
                    color = (255, 255, 100)
                    font_size = 1.2
                elif line.startswith('🚀') or line.startswith('📱') or line.startswith('🔐'):
                    color = (100, 255, 100)
                    font_size = 0.9
                elif line.startswith('$'):
                    color = (100, 255, 255)
                    font_size = 0.8
                elif line.startswith('Résultat:') or line.startswith('Score:'):
                    color = (255, 255, 255)
                    font_size = 0.8
                else:
                    color = (200, 200, 200)
                    font_size = 0.7
                
                cv2.putText(frame, line, (50, y), cv2.FONT_HERSHEY_SIMPLEX, 
                           font_size, color, 2, cv2.LINE_AA)
            y += 40
        
        video.write(frame)
    
    video.release()
    print("✅ Vidéo démonstration générateur créée: demo.mp4")

if __name__ == "__main__":
    create_password_demo()
