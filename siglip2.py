import os
import json
import torch
import numpy as np
from PIL import Image
from transformers import AutoProcessor, AutoModel
from huggingface_hub import login

# ---------------------------
# HUGGINGFACE LOGIN
# ---------------------------
HF_TOKEN = "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"  # Replace with your actual key
if HF_TOKEN and HF_TOKEN != "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":
    login(token=HF_TOKEN)
else:
    print("HF_TOKEN not set or default! Make sure to set it to access private/gated models.")

# ---------------------------
# CONFIG
# ---------------------------
DATASET_DIR = "downloaded_images"
PRODUCT_JSON = "prod-cleaned.json"
CROP_PRODUCT_JSON = "prod-all-crop-results.json"

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MODEL_ID = "google/siglip2-giant-opt-patch16-384"

# ---------------------------
# LOAD MODEL (OPTIMIZED)
# ---------------------------
print("Loading processor...")
processor = AutoProcessor.from_pretrained(MODEL_ID)

print(f"Loading model '{MODEL_ID}' in FP16 precision on {DEVICE}...")
model = AutoModel.from_pretrained(
    MODEL_ID,
    torch_dtype=torch.float16 # Speeds up inference and halves VRAM usage
)
model = model.to(DEVICE)
model.eval()


# ---------------------------
# IMAGE EMBEDDING (BATCHED)
# ---------------------------
def get_image_embeddings(image_paths):
    """Processes a LIST of images simultaneously for massive speedups."""
    if not image_paths:
        return []

    # Open all images at once
    images = [Image.open(path).convert("RGB") for path in image_paths]

    # Process them into a single batch
    inputs = processor(images=images, return_tensors="pt").to(DEVICE)
    
    # Cast image inputs to match the model's FP16 weights
    if "pixel_values" in inputs:
        inputs["pixel_values"] = inputs["pixel_values"].to(torch.float16)

    # Use inference_mode instead of no_grad for extra speed
    with torch.inference_mode():
        outputs = model.get_image_features(**inputs)

    if isinstance(outputs, torch.Tensor):
        vecs = outputs
    else:
        vecs = getattr(outputs, "image_embeds", None) or getattr(outputs, "pooler_output", None)

    # Normalize the entire batch at once
    vecs = vecs / vecs.norm(dim=-1, keepdim=True)

    # Move back to CPU and convert to standard float32 for NumPy compatibility
    return vecs.cpu().numpy().astype(np.float32)


# ---------------------------
# TEXT EMBEDDING (ORIGINAL LOGIC)
# ---------------------------
def get_text_embedding(text):
    if text is None or len(text.strip()) == 0:
        return None

    # Reverted to your exact original logic, just added inference_mode for speed
    inputs = processor(text=text, return_tensors="pt").to(DEVICE)

    with torch.inference_mode():
        outputs = model.get_text_features(**inputs)

    if isinstance(outputs, torch.Tensor):
        vec = outputs
    else:
        vec = getattr(outputs, "text_embeds", None) or getattr(outputs, "pooler_output", None)

    vec = vec / vec.norm(dim=-1, keepdim=True)

    return vec.cpu().numpy()[0].astype(np.float32)


# ---------------------------
# COMBINE IMAGE EMBEDDINGS
# ---------------------------
def combine_image_embeddings(image_embeddings):
    emb = np.mean(image_embeddings, axis=0)
    emb = emb / np.linalg.norm(emb)
    return emb


# ---------------------------
# FETCH DESCRIPTION
# ---------------------------
def fetch_description(product_id, image_name, description_json):
    product = next((p for p in description_json if p.get("product_id") == product_id), None)
    if not product:
        return ""

    image_entry = next(
        (
            img
            for img in product.get("images", [])
            if img.get("image") == image_name and img.get("type") == "product_description"
        ),
        None,
    )

    if image_entry:
        return image_entry.get("description", "")

    return ""


# ---------------------------
# STORAGE
# ---------------------------
all_image_embeddings = []
all_text_embeddings = []
all_metadata = []


# ---------------------------
# LOAD DATA
# ---------------------------
print("Loading JSON data...")
try:
    with open(PRODUCT_JSON, "r") as f:
        products = json.load(f)

    with open(CROP_PRODUCT_JSON, "r") as f:
        description_products = json.load(f)
except FileNotFoundError as e:
    print(f"Error loading JSON files: {e}")
    exit(1)


# ---------------------------
# PROCESS PRODUCTS
# ---------------------------
print(f"Starting processing for {len(products)} products...")

for product in products:
    product_id = product.get("product_id")
    brand = product.get("brand", "Unknown")
    category = product.get("category", "Unknown")
    product_name = product.get("productName", "")
    url = product.get("url", "")
    price = product.get("price", "")

    folder = os.path.join(DATASET_DIR, product_id)

    if not os.path.exists(folder):
        print(f"Missing folder: {folder}")
        continue

    images = sorted(
        [img for img in os.listdir(folder) if img.lower().endswith(("jpg", "jpeg", "png"))]
    )

    # Skip the first context image (s.jpg)
    img_names_to_process = images[1:] 
    if not img_names_to_process:
        continue

    # 1. Create a list of full paths
    img_paths = [os.path.join(folder, img_name) for img_name in img_names_to_process]
    
    # 2. Grab descriptions
    descriptions = []
    for img_name in img_names_to_process:
        desc = fetch_description(product_id, img_name, description_products)
        if desc:
            descriptions.append(desc)

    try:
        # 3. GET ALL IMAGE EMBEDDINGS IN ONE FAST BATCH
        image_embeddings_batch = get_image_embeddings(img_paths)
        
        if len(image_embeddings_batch) == 0:
            continue

        # Combine them (average out the batch)
        product_image_embedding = combine_image_embeddings(image_embeddings_batch)

        # 4. Get text embedding
        combined_description = " ".join(descriptions)
        text_emb = get_text_embedding(combined_description)
        
        if text_emb is None:
            # Fallback if no text was generated or found
            text_emb = np.zeros_like(product_image_embedding)

        # 5. Store results
        all_image_embeddings.append(product_image_embedding)
        all_text_embeddings.append(text_emb)

        all_metadata.append({
            "product_id": product_id,
            "brand": brand,
            "category": category,
            "product_name": product_name,
            "url": url,
            "price": price,
            "description": combined_description
        })

        print(f"Processed product: {product_id} ({len(img_paths)} images)")

    except Exception as e:
        print(f"Failed on product {product_id}: {e}")

# ---------------------------
# CONVERT TO MATRIX
# ---------------------------
print("\nConverting embeddings to matrices...")
if all_image_embeddings:
    all_image_embeddings_matrix = np.vstack(all_image_embeddings)
    all_text_embeddings_matrix = np.vstack(all_text_embeddings)

    # ---------------------------
    # SAVE RESULTS
    # ---------------------------
    print("Saving results...")
    np.save("image_embeddings_biglip.npy", all_image_embeddings_matrix)
    np.save("text_embeddings_biglip.npy", all_text_embeddings_matrix)

    with open("metadata_biglip.json", "w") as f:
        json.dump(all_metadata, f, indent=2)

    print("Done.")
    print(f"Products successfully processed: {len(all_metadata)}")
else:
    print("No products were processed successfully. Check your directories and JSON files.")