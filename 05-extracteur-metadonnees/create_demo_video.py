import cv2
import numpy as np

def create_metadata_demo():
    width, height = 1280, 720
    fps = 1
    duration = 16
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video = cv2.VideoWriter('demo.mp4', fourcc, fps, (width, height))
    
    demo_sequence = [
        ["🎬 DÉMONSTRATION: Extracteur de Métadonnées", ""],
        ["", "Outil d'analyse complète de fichiers"],
        ["📂 Types de fichiers supportés:", "Images: JPEG, PNG, TIFF, BMP (EXIF)"],
        ["", "Documents: PDF, DOCX, TXT"],
        ["", "Audio/Vidéo: MP3, MP4, AVI (Tags)"],
        ["🔍 Exemple d'extraction:", "$ python metadata_extractor.py test_document.txt"],
        ["📊 Informations extraites:", "- Nom: test_document.txt"],
        ["", "- Taille: 33 bytes"],
        ["", "- Type MIME: text/plain"],
        ["", "- Encodage: UTF-8"],
        ["🔐 Empreintes calculées:", "MD5: 763c0dc64153e8b3e1f8687fbd004d84"],
        ["", "SHA1: bffadc0719c7d13a5d9530bfd6bd7433a3f61cf6"],
        ["", "SHA256: 3ec9e99ed65470e4d286066b9972fefc..."],
        ["📈 Analyse de contenu:", "Caractères: 31 | Mots: 4 | Lignes: 2"],
        ["📁 Export formats:", "JSON, CSV, XML disponibles"],
        ["✅ Métadonnées complètes extraites!", "Outil professionnel d'analyse forensique"]
    ]
    
    for frame_idx in range(duration * fps):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Fond vert foncé style matrice
        for i in range(height):
            intensity = int(15 + (i / height) * 25)
            frame[i, :] = [intensity//2, intensity*2, intensity]
        
        current_frame = min(frame_idx, len(demo_sequence)-1)
        lines = demo_sequence[current_frame]
        
        y = 160
        for line in lines:
            if line:
                if line.startswith('🎬'):
                    color = (100, 255, 255)
                    size = 1.1
                elif line.startswith('📂') or line.startswith('🔍') or line.startswith('📊'):
                    color = (100, 255, 150)
                    size = 0.9
                elif line.startswith('$'):
                    color = (150, 255, 100)
                    size = 0.8
                elif 'MD5:' in line or 'SHA' in line:
                    color = (255, 255, 100)
                    size = 0.7
                elif line.startswith('- '):
                    color = (200, 255, 200)
                    size = 0.7
                else:
                    color = (180, 255, 180)
                    size = 0.8
                
                cv2.putText(frame, line, (40, y), cv2.FONT_HERSHEY_SIMPLEX,
                           size, color, 2, cv2.LINE_AA)
            y += 35
        
        video.write(frame)
    
    video.release()
    print("✅ Vidéo extracteur de métadonnées créée: demo.mp4")

if __name__ == "__main__":
    create_metadata_demo()
