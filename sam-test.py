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
