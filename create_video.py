import cv2
import numpy as np
import subprocess
import tempfile
import os

def create_text_video(text_file, output_video, fps=2, duration=10):
    # Lire le contenu du fichier
    with open(text_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Configuration vidéo
    width, height = 1280, 720
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video_writer = cv2.VideoWriter(output_video, fourcc, fps, (width, height))
    
    # Créer les frames
    lines = content.split('\n')
    total_frames = fps * duration
    lines_per_frame = max(1, len(lines) // total_frames)
    
    for frame_num in range(total_frames):
        # Créer une image noire
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Calculer quelles lignes afficher
        start_line = frame_num * lines_per_frame
        end_line = min(start_line + 20, len(lines))  # Afficher 20 lignes max
        
        # Ajouter le texte
        y_pos = 50
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Nettoyer les caractères de contrôle
                clean_line = ''.join(c for c in line if ord(c) >= 32 or c in ['\t', '\n'])
                if clean_line.strip():
                    cv2.putText(frame, clean_line[:100], (20, y_pos), 
                              cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 1)
                    y_pos += 25
                    if y_pos > height - 50:
                        break
        
        video_writer.write(frame)
    
    video_writer.release()
    print(f"Vidéo créée: {output_video}")

# Exécuter la création de vidéo
if __name__ == "__main__":
    create_text_video('/tmp/demo_output.txt', 'demo.mp4')
