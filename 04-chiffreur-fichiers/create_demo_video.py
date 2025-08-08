import cv2
import numpy as np

def create_encryptor_demo():
    width, height = 1280, 720
    fps = 1
    duration = 20
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video = cv2.VideoWriter('demo.mp4', fourcc, fps, (width, height))
    
    demo_slides = [
        ["🎬 DÉMONSTRATION: Chiffreur de Fichiers", ""],
        ["", "Application desktop Tkinter avec AES-256"],
        ["🖥️ Interface graphique moderne:", "- Onglets: Chiffrement/Historique/À propos"],
        ["", "- Support drag & drop"],
        ["", "- Barre de progression en temps réel"],
        ["📁 Sélection de fichiers:", "✅ rapport_confidentiel.pdf (2.4 MB)"],
        ["", "✅ photos_vacances.zip (15.7 MB)"],
        ["", "✅ code_source/ (47 fichiers, 8.2 MB)"],
        ["🔐 Configuration chiffrement:", "Mot de passe: MonMotDePasseSecure123!"],
        ["", "Confirmation: ✅ Mot de passe confirmé"],
        ["🚀 Processus de chiffrement:", "🔄 Génération clé PBKDF2 (100k itérations)"],
        ["", "🔄 Chiffrement AES-256-GCM via Fernet"],
        ["", "🔄 Métadonnées intégrées (nom, date, taille)"],
        ["📊 Progression:", "[████████████████████████] 75%"],
        ["", "3/4 fichiers traités"],
        ["✅ Résultats:", "✅ rapport_confidentiel.pdf.fenc"],
        ["", "✅ photos_vacances.zip.fenc"],
        ["", "✅ code_source.fenc"],
        ["🛡️ Format propriétaire .fenc:", "- Signature FENC + version"],
        ["", "- Sel unique par fichier"],
        ["", "- Vérification d'intégrité"],
        ["📈 Historique chiffré:", "- Toutes opérations enregistrées"],
        ["", "- Export JSON/TXT disponible"],
        ["✨ Sécurité de niveau bancaire:", "Vos fichiers sont protégés!"]
    ]
    
    for frame_idx in range(duration * fps):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Fond dégradé violet/bleu
        for i in range(height):
            intensity = int(30 + (i / height) * 40)
            frame[i, :] = [intensity*2, intensity, intensity*3]
        
        current_slide = min(frame_idx, len(demo_slides)-1)
        lines = demo_slides[current_slide]
        
        y = 180
        for line in lines:
            if line:
                if line.startswith('🎬'):
                    color = (255, 255, 150)
                    size = 1.2
                elif line.startswith('🖥️') or line.startswith('📁') or line.startswith('🔐'):
                    color = (150, 255, 150)
                    size = 0.9
                elif line.startswith('✅') or line.startswith('🔄'):
                    color = (255, 255, 255)
                    size = 0.8
                elif 'MB)' in line or '.fenc' in line:
                    color = (200, 255, 200)
                    size = 0.7
                elif line.startswith('- '):
                    color = (180, 180, 255)
                    size = 0.7
                else:
                    color = (220, 220, 220)
                    size = 0.8
                
                cv2.putText(frame, line, (50, y), cv2.FONT_HERSHEY_SIMPLEX,
                           size, color, 2, cv2.LINE_AA)
            y += 32
        
        video.write(frame)
    
    video.release()
    print("✅ Vidéo chiffreur de fichiers créée: demo.mp4")

if __name__ == "__main__":
    create_encryptor_demo()
