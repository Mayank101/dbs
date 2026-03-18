import os
import json
import time
import random
import torch
import numpy as np
from PIL import Image
from dotenv import load_dotenv

# Hugging Face & Ultralytics
from huggingface_hub import login, hf_hub_download
from ultralytics import YOLO
from PIL import Image, ImageOps
from transformers import Sam3Processor, Sam3Model

# Google Vertex AI (Gemini 2.0 Flash)
from google.oauth2 import service_account
import vertexai
from vertexai.generative_models import GenerativeModel, Part

# ---------------------------
# CONFIGURATION
# ---------------------------
DATASET_DIR = "downloaded_images"
PRODUCT_JSON = "sample.json"
OUTPUT_JSON = "prod-sam3-results.json"
CROPPED_DIR = "boots-sam3-transparent" 

MAX_RETRIES = 5
CONF_THRESHOLD = 0.3

# Intelligently target the best available hardware (Apple Silicon, Nvidia, or CPU)
DEVICE = "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"

os.makedirs(CROPPED_DIR, exist_ok=True)
load_dotenv()

# ---------------------------
# INITIALIZE APIs & MODELS
# ---------------------------
print(f"Starting Initialization on computing device: {DEVICE.upper()}...")

# 1. Hugging Face Login
HF_TOKEN = "your_key" # Replace with your actual HF token
if HF_TOKEN and HF_TOKEN != "your_key":
    login(token=HF_TOKEN)
else:
    print("Warning: HF_TOKEN not set properly!")

# 2. Vertex AI (Gemini)
SERVICE_ACCOUNT_FILE = "maven-slikk-search-7179aa0295bc.json"
try:
    credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE)
    vertexai.init(project=credentials.project_id, credentials=credentials)
    gemini_model = GenerativeModel("gemini-2.5-flash")
    print("Vertex AI (Gemini) initialized.")
except Exception as e:
    print(f"Error loading service account: {e}")
    exit(1)

# 3. BRAIN 1: DeepFashion2 (Garments)
print("Downloading/Loading DeepFashion2 YOLOv8 weights...")
try:
    fashion_model_path = hf_hub_download(repo_id="Bingsu/adetailer", filename="deepfashion2_yolov8s-seg.pt")
    fashion_model = YOLO(fashion_model_path) 
    print("Fashion YOLO loaded successfully.")
except Exception as e:
    print(f"Error loading Fashion YOLO: {e}")
    exit(1)

# 4. BRAIN 2: Open Images V7 (Accessories & Footwear)
print("Downloading/Loading Open Images V7 YOLOv8 weights...")
try:
    accessory_model = YOLO("yolov8m-oiv7.pt")
    print("Accessory YOLO loaded successfully.")
except Exception as e:
    print(f"Error loading Accessory YOLO: {e}")
    exit(1)

# 5. Meta SAM 3 
print("Loading official Meta SAM 3 model...")
SAM_MODEL_ID = "facebook/sam3" 
try:
    sam_processor = Sam3Processor.from_pretrained(SAM_MODEL_ID, token=HF_TOKEN)
    sam_model = Sam3Model.from_pretrained(SAM_MODEL_ID, token=HF_TOKEN).to(DEVICE)
    sam_model.eval()
    print("SAM 3 loaded successfully.")
except Exception as e:
    print(f"Error loading SAM 3: {e}")
    exit(1)

print("\nAll systems go! Ready to process.\n" + "-"*40)


# ---------------------------
# PIPELINE FUNCTIONS
# ---------------------------

def get_yolo_boxes(image_path, main_product_name):
    """Step 1: Two-Brain detection (No hardcoded filters). Grabs EVERYTHING it sees."""
    items = []
    
    # --- Brain 1: DeepFashion2 (Clothes) ---
    results_fashion = fashion_model(image_path, conf=CONF_THRESHOLD, verbose=False)[0]
    if results_fashion.boxes is not None:
        for box in results_fashion.boxes:
            x1, y1, x2, y2 = box.xyxy[0].tolist()
            label_name = fashion_model.names[int(box.cls[0].item())].lower().replace("_", " ")
            
            if main_product_name and label_name == main_product_name.lower():
                continue  
                
            items.append({
                "item_name": label_name, 
                "bbox": [int(x1), int(y1), int(x2), int(y2)], 
                "source": "fashion"
            })

    # --- Brain 2: Open Images V7 (Everything Else) ---
    results_accessories = accessory_model(image_path, conf=0.15, verbose=False)[0]
    if results_accessories.boxes is not None:
        for box in results_accessories.boxes:
            x1, y1, x2, y2 = box.xyxy[0].tolist()
            label_name = accessory_model.names[int(box.cls[0].item())].lower().replace("_", " ")
            
            if main_product_name and label_name == main_product_name.lower():
                continue
                
            items.append({
                "item_name": label_name, 
                "bbox": [int(x1), int(y1), int(x2), int(y2)], 
                "source": "accessory"
            })

    return items


def generate_gemini_descriptions(image_path, detected_items):
    """Step 2: Ask Gemini 2.0 Flash to semantically filter out garbage and enrich valid items."""
    if not detected_items:
        return []

    prompt = f"""
    The following objects were detected in this image: {[item['item_name'] for item in detected_items]}
    
    You are an intelligent Fashion AI Filter.
    1. Evaluate each item. If it is NOT a piece of clothing, footwear, bag, jewelry, or fashion accessory (for example, completely ignore "person", "man", "woman", "wall", "car", "human face", "human arm"), you MUST exclude it from your response entirely.
    2. For the VALID fashion and accessory items ONLY, provide:
       - "item_name": The exact original name from the list.
       - "category": The best fashion category.
       - "short_description": A 10-word visual description.
       - "long_description": A highly detailed 45-word description covering material, style, and fit.

    Return JSON strictly in this format:
    {{
        "items": [
            {{"item_name": "", "category": "", "short_description": "", "long_description": ""}}
        ]
    }}
    """
    
    with open(image_path, "rb") as f:
        image_part = Part.from_data(data=f.read(), mime_type="image/jpeg")

    for attempt in range(MAX_RETRIES):
        try:
            response = gemini_model.generate_content(
                [image_part, prompt],
                generation_config={"temperature": 0.1, "response_mime_type": "application/json"}
            )
            data = json.loads(response.text)
            
            # Cross-reference Gemini's filtered list with our original YOLO boxes
            valid_items = []
            for g_item in data.get("items", []):
                # Find the matching YOLO box for the item Gemini approved
                matching_yolo = next((y for y in detected_items if y["item_name"] == g_item["item_name"]), None)
                if matching_yolo:
                    matching_yolo["category"] = g_item.get("category", g_item["item_name"])
                    matching_yolo["short_description"] = g_item.get("short_description", "")
                    matching_yolo["long_description"] = g_item.get("long_description", "")
                    valid_items.append(matching_yolo)
                    
            return valid_items

        except Exception as e:
            if "429" in str(e) or "Resource exhausted" in str(e):
                sleep_time = (2 ** attempt) + random.uniform(0, 1)
                print(f"Rate limit hit. Sleeping {sleep_time:.1f}s before retry...")
                time.sleep(sleep_time)
            else:
                print(f"Gemini error: {e}")
                return []
                
    return []


def create_transparent_cutout(image_path, bbox, text_prompt, save_path):
    """Step 3: Official SAM 3 cuts out the item using BOTH text and box prompts."""
    image = Image.open(image_path)
    image = ImageOps.exif_transpose(image).convert("RGB")
    
    # Level 1 (Batch) -> Level 2 (Boxes) -> Level 3 (Coordinates)
    input_boxes = [[bbox]] 
    input_boxes_labels = [[1]] 
    
    inputs = sam_processor(
        images=image, 
        text=text_prompt, 
        input_boxes=input_boxes,
        input_boxes_labels=input_boxes_labels,
        return_tensors="pt"
    ).to(DEVICE)

    with torch.inference_mode():
        outputs = sam_model(**inputs)

    # Use SAM 3's official post-processing function
    results = sam_processor.post_process_instance_segmentation(
        outputs,
        threshold=0.1,
        mask_threshold=0.5,
        target_sizes=[(image.height, image.width)]
    )[0]
    
    # Safety check
    if len(results["masks"]) == 0:
        raise ValueError(f"SAM 3 returned an empty mask for '{text_prompt}'")
    
    # Extract the boolean mask array
    mask_array = results["masks"][0].cpu().numpy()

    # Composite the mask onto an alpha (transparency) channel
    image_rgba = image.convert("RGBA")
    alpha_channel = Image.fromarray((mask_array * 255).astype(np.uint8), mode='L')
    
    transparent_img = Image.new("RGBA", image_rgba.size, (0, 0, 0, 0))
    transparent_img.paste(image_rgba, mask=alpha_channel)
    
    # Crop away the empty transparent space right down to the bounding box
    cropped_img = transparent_img.crop(bbox)
    cropped_img.save(save_path, format="PNG")
    
    return save_path


# ---------------------------
# MAIN EXECUTION
# ---------------------------

def process_product(product):
    product_id = product.get("product_id")
    product_name = product.get("productName", "")
    
    img_path = os.path.join(DATASET_DIR, product_id, f"{product_id}_s.jpg")
    
    if not os.path.exists(img_path):
        return product

    print(f"\nProcessing {product_id}...")
    
    # 1. YOLO Detection (Gets EVERYTHING from both brains)
    raw_items = get_yolo_boxes(img_path, product_name)
    
    # 2. Gemini Enrichment & Filtering (Drops the garbage, keeps the fashion)
    clean_items = generate_gemini_descriptions(img_path, raw_items)
    
    if not clean_items:
        print(f"  -> No valid fashion items or accessories detected.")
        return product

    product_crop_folder = os.path.join(CROPPED_DIR, product_id)
    os.makedirs(product_crop_folder, exist_ok=True)

    # 3. Draw Custom Unified Debug Image (Using only clean_items)
    try:
        annotated_img = Image.open(img_path).convert("RGB")
        annotated_img = ImageOps.exif_transpose(annotated_img)
        draw = ImageDraw.Draw(annotated_img)
        
        for item in clean_items:
            x1, y1, x2, y2 = item["bbox"]
            label = item["category"] # Use the clean Gemini category for the label
            color = "blue" if item["source"] == "fashion" else "red"
            
            draw.rectangle([x1, y1, x2, y2], outline=color, width=4)
            text_bbox = draw.textbbox((x1, y1), label)
            draw.rectangle([text_bbox[0], text_bbox[1], text_bbox[2], text_bbox[3]], fill=color)
            draw.text((x1, y1), label, fill="white")
            
        annotated_save_path = os.path.join(product_crop_folder, f"{product_id}_unified_boxes.jpg")
        annotated_img.save(annotated_save_path)
        print(f"  -> Saved unified YOLO visualization to: {product_id}_unified_boxes.jpg")
    except Exception as e:
        print(f"  -> Failed to generate debug image: {e}")

    # 4. SAM 3 Masking & Saving
    for item in clean_items:
        try:
            category_safe = item["category"].replace(" ", "_").replace("/", "-")
            save_name = f"{product_id}_{category_safe}.png"
            save_path = os.path.join(product_crop_folder, save_name)
            
            # Feed SAM 3 the image, the box, AND the Gemini text description
            create_transparent_cutout(img_path, item["bbox"], item["short_description"], save_path)
            
            item["cutout_path"] = save_path
            print(f"  -> Successfully extracted transparent PNG: {save_name} (from {item['source']})")
            
        except Exception as e:
            print(f"  -> Failed to segment {item['item_name']}: {e}")

    product["context_items"] = clean_items
    return product

def main():
    try:
        with open(PRODUCT_JSON, "r") as f:
            products = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {PRODUCT_JSON}")
        return

    results = []
    total_start = time.time()
    
    for product in products:
        results.append(process_product(product))

    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)

    total_time = time.time() - total_start
    print(f"\nPipeline complete in {total_time / 60:.1f} minutes!")
    print(f"Check the '{CROPPED_DIR}' folder for your pixel-perfect PNGs.")

if __name__ == "__main__":
    main()