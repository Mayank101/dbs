from huggingface_hub import login
HF_TOKEN = "your_key" # Replace with your actual HF token
login (token = HF_TOKEN)

from transformers import Sam3Processor, Sam3Model 
from PIL import Image 
import torch 
import requests 
import numpy as np 
import os
from io import BytesIO


# # Loaing using hf token
# device = "cuda" if torch.cuda. is_available() else "cpu"
# try:
#     processor = Sam3Processor.from_pretrained ("facebook/sam3")
#     model = Sam3Model.from_pretrained ("facebook/sam3"). to (device)
#     print("SAM 3 successfully loaded!")
# except Exception as e:
#     print(f"Error loading SAM 3: {e}")
#     print("Ensure you have accepted the license on Hugging Face and ran 'huggingface-cli login'.")

# 4. Meta SAM 3 
DEVICE = "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"
print(f"Using compute device: {DEVICE}")

# 4. Meta SAM 3 
print("Loading official Meta SAM 3 model...")
SAM_MODEL_ID = "facebook/sam3" 
try:
    # Force the token directly into the loaders
    sam_processor = Sam3Processor.from_pretrained(SAM_MODEL_ID, token=HF_TOKEN)
    sam_model = Sam3Model.from_pretrained(SAM_MODEL_ID, token=HF_TOKEN).to(DEVICE)
    sam_model.eval()
    print("SAM 3 loaded successfully.")
except Exception as e:
    print(f"Error loading SAM 3: {e}")
    exit(1)