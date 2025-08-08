import cv2
import numpy as np

def create_ssl_demo():
    width, height = 1280, 720
    fps = 1
    duration = 18
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video = cv2.VideoWriter('demo.mp4', fourcc, fps, (width, height))
    
    demo_frames = [
        ["🎬 DÉMONSTRATION: Vérificateur SSL/TLS", ""],
        ["", "Outil professionnel d'audit de certificats"],
        ["🔍 Interface double: CLI + GUI Tkinter", "$ python ssl_checker.py --gui"],
        ["", "🖥️ Interface graphique avec onglets"],
        ["🌐 Vérification de certificats:", "Hôtes: google.com, facebook.com, github.com"],
        ["", "📊 Vérification parallèle (10 threads)"],
        ["", "⏱️ Timeout: 10 secondes par connexion"],
        ["✅ Résultats de vérification:", "🟢 google.com:443 - Valide (Score: 95/100)"],
        ["", "   Émetteur: Google Trust Services"],
        ["", "   Expire: 2024-12-15 (127 jours restants)"],
        ["", "   Protocole: TLS 1.3, AES-256-GCM"],
        ["🟢 github.com:443 - Valide (Score: 92/100)", "   Émetteur: DigiCert Inc"],
        ["", "   Clé RSA 2048 bits"],
        ["📊 Analyse de sécurité avancée:", "- Algorithmes de chiffrement"],
        ["", "- Dates d'expiration"],
        ["", "- Chaîne de certification"],
        ["🚨 Monitoring automatique:", "Vérifications programmées toutes les 24h"],
        ["", "Alertes: 7, 30, 90 jours avant expiration"],
        ["📄 Rapports détaillés:", "Export HTML, CSV, JSON disponible"],
        ["✨ Outil professionnel complet!", "Surveillance proactive des certificats"]
    ]
    
    for frame_idx in range(duration * fps):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Fond bleu sécurité
        for i in range(height):
            intensity = int(20 + (i / height) * 35)
            frame[i, :] = [intensity*3, intensity*2, intensity]
        
        current_frame = min(frame_idx, len(demo_frames)-1)
        lines = demo_frames[current_frame]
        
        y = 150
        for line in lines:
            if line:
                if line.startswith('🎬'):
                    color = (255, 255, 150)
                    size = 1.2
                elif line.startswith('🔍') or line.startswith('🌐') or line.startswith('📊'):
                    color = (150, 200, 255)
                    size = 0.9
                elif line.startswith('$'):
                    color = (150, 255, 150)
                    size = 0.8
                elif line.startswith('🟢'):
                    color = (100, 255, 100)
                    size = 0.8
                elif 'Score:' in line or 'TLS' in line:
                    color = (255, 255, 255)
                    size = 0.7
                elif line.startswith('   '):
                    color = (200, 200, 255)
                    size = 0.7
                else:
                    color = (220, 220, 220)
                    size = 0.8
                
                cv2.putText(frame, line, (45, y), cv2.FONT_HERSHEY_SIMPLEX,
                           size, color, 2, cv2.LINE_AA)
            y += 32
        
        video.write(frame)
    
    video.release()
    print("✅ Vidéo vérificateur SSL créée: demo.mp4")

if __name__ == "__main__":
    create_ssl_demo()
