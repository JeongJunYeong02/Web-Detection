import torch
from PIL import Image
import torchvision.transforms as T
import torch.nn as nn
import numpy as np
from skimage.metrics import structural_similarity as ssim

MODEL_PATH = "/Users/jeongjun-yeong/Desktop/opencv/ssssss/graduation/server/autoencoder_trained_multi.pth"
IMG1_PATH = "/Users/jeongjun-yeong/Desktop/opencv/ssssss/graduation/server/images/class1/1.png"
IMG2_PATH = "/Users/jeongjun-yeong/Desktop/opencv/ssssss/graduation/server/images/class1/1.png"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ============ 모델 구조 동일 ============
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

# ============ 불러오기 ============
model = AutoEncoder().to(device)
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
model.eval()

transform = T.Compose([
    T.Resize((256, 256)),
    T.ToTensor()
])

def compare_images(img1, img2):
    img1_resized = img1.resize((256, 256))
    img2_resized = img2.resize((256, 256))
    img1_np = np.array(img1_resized)
    img2_np = np.array(img2_resized)
    ssim_score = ssim(img1_np, img2_np, channel_axis=-1)
    mse_score = np.mean((img1_np - img2_np) ** 2)
    combined = (ssim_score * 100) - (mse_score * 50)
    return max(0, min(100, combined))

def encode_image(path):
    img = Image.open(path).convert("RGB")
    img_tensor = transform(img).unsqueeze(0).to(device)
    with torch.no_grad():
        encoded = model.encoder(img_tensor)
        encoded = torch.nn.functional.normalize(encoded, p=2, dim=1)
    return encoded.squeeze().cpu()

# ============ 유사도 계산 ============
encoded1 = encode_image(IMG1_PATH)
encoded2 = encode_image(IMG2_PATH)

# 벡터 거리 기반 유사도 추가
cos_sim = torch.nn.functional.cosine_similarity(encoded1.flatten(), encoded2.flatten(), dim=0)
img1 = Image.open(IMG1_PATH).convert("RGB")
img2 = Image.open(IMG2_PATH).convert("RGB")
structural = compare_images(img1, img2)

final_score = ((cos_sim.item() * 0.7) + (structural / 100 * 0.3)) * 100

print(f"📊 코사인 유사도 기반: {cos_sim.item() * 100:.2f}%")
print(f"📸 구조 유사도 기반: {structural:.2f}%")
print(f"✅ 최종 결합 유사도: {final_score:.2f}%")
