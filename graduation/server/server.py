# server.py (SSIM 최종 수정본: win_size 및 channel_axis 명시)

from flask import Flask, request, jsonify
from flask_cors import CORS
from web_forgery_detector import WebForgeryDetector 
import traceback
import json
import os
import base64
import io
from PIL import Image

# ------------------ Flask 초기화 ------------------
app = Flask(__name__)
CORS(app)

# ------------------ 경로 설정 ------------------
base_dir = os.path.dirname(os.path.abspath(__file__))

# ------------------ 1. 웹 위변조 탐지기 ------------------
print("탐지기 초기화 중...")
try:
    detector = WebForgeryDetector(
        whitelist_csv_path=os.path.join(base_dir, "top10.csv"),
        baseline_html_path=os.path.join(base_dir, "normal.html"),
        baseline_url="http://localhost:8000/normal.html#"
    )
    print("✅ 탐지기 초기화 완료!")
except Exception as e:
    print(f"❌ 탐지기 로드 실패: {e}")
    detector = None

@app.route('/check_current_page', methods=['POST'])
def check_current_page():
    if detector is None:
        return jsonify({"error": "WebForgeryDetector가 로드되지 않았습니다."}), 500
    try:
        data = request.json
        print(f"\n[웹 분석] URL: {data.get('url', 'Unknown')}")
        results = detector.analyze_with_baseline(data.get('html', ''), data.get('url', ''))
        print(f"웹 분석 완료 ✅ 위험도: {results['risk_assessment']['risk_score']}점")
        return jsonify(results)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ------------------ 2. 이미지 유사도 분석 ------------------
import torch
import torchvision.transforms as T
import torch.nn as nn
import numpy as np
from skimage.metrics import structural_similarity as ssim

MODEL_PATH = os.path.join(base_dir, "autoencoder_trained_multi.pth")
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class AutoEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Conv2d(3, 32, 3, stride=2, padding=1), nn.ReLU(),
            nn.Conv2d(32, 64, 3, stride=2, padding=1), nn.ReLU(),
            nn.Conv2d(64, 128, 3, stride=2, padding=1), nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.ConvTranspose2d(128, 64, 3, stride=2, padding=1, output_padding=1), nn.ReLU(),
            nn.ConvTranspose2d(64, 32, 3, stride=2, padding=1, output_padding=1), nn.ReLU(),
            nn.ConvTranspose2d(32, 3, 3, stride=2, padding=1, output_padding=1), nn.Sigmoid()
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))

try:
    print("🔹 AutoEncoder 로드 중...")
    model = AutoEncoder().to(device)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()
    print("✅ AutoEncoder 로드 완료!")
except Exception as e:
    print(f"❌ 모델 로드 실패: {e}")
    model = None

transform = T.Compose([T.Resize((256, 256)), T.ToTensor()])

def compare_images_v2(img1_pil, img2_pil):
    """ ★ [수정] 에러 메시지 요구사항 반영 """
    img1_resized = img1_pil.resize((256, 256)).convert("RGB")
    img2_resized = img2_pil.resize((256, 256)).convert("RGB")
    
    img1_np = np.array(img1_resized)
    img2_np = np.array(img2_resized)
    
    # ★★★ [수정] 에러 메시지가 요구한 파라미터를 모두 추가합니다. ★★★
    score = ssim(img1_np, img2_np, 
                 win_size=7,          # 1. 윈도우 크기 명시
                 channel_axis=-1,     # 2. 컬러 채널 축 명시 (RGB가 마지막 축)
                 data_range=255       # 3. 데이터 범위 명시
                )
    
    return max(0, min(100, score * 100)) # 0~100점 스케일로 변환

def load_image_from_base64(data_url):
    header, encoded = data_url.split(',', 1)
    return Image.open(io.BytesIO(base64.b64decode(encoded))).convert("RGB")

def encode_image(img_pil):
    img_tensor = transform(img_pil).unsqueeze(0).to(device)
    with torch.no_grad():
        encoded = model.encoder(img_tensor)
    return encoded.squeeze().cpu()

@app.route('/analyze', methods=['POST'])
def analyze_images():
    if model is None: return jsonify({"error": "AI 모델 없음"}), 500
    try:
        data = request.json
        img1_path = os.path.join(base_dir, data.get("img1_path"))
        img2_data = data.get("img2_data")

        print(f"\n[이미지 분석 요청] 기준: {os.path.basename(img1_path)} vs 스냅샷")

        if not os.path.exists(img1_path): return jsonify({"error": "기준 이미지 없음"}), 404
        if not img2_data: return jsonify({"error": "스냅샷 데이터 없음"}), 400

        img1_pil = Image.open(img1_path).convert("RGB")
        img2_pil = load_image_from_base64(img2_data)

        vec1 = encode_image(img1_pil).flatten()
        vec2 = encode_image(img2_pil).flatten()
        cosine_score = torch.nn.functional.cosine_similarity(vec1, vec2, dim=0).item()

        structural_score = compare_images_v2(img1_pil, img2_pil)

        final_score = (cosine_score * 50) + (structural_score * 0.5)
        
        print(f"📊 코사인 점수: {cosine_score:.4f} -> 환산: {cosine_score * 50:.2f}/50")
        print(f"📸 구조(SSIM): {structural_score:.2f} -> 환산: {structural_score * 0.5:.2f}/50")
        print(f"✅ 최종 결합: {final_score:.2f}/100")

        return jsonify({
            "cosine": cosine_score * 100,
            "structural": structural_score,
            "final": final_score
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ------------------ 실행 ------------------
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=True)