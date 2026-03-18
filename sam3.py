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

# 3. DeepFashion2 Trained YOLOv8
print("Downloading/Loading DeepFashion2 YOLOv8 weights...")
try:
    fashion_model_path = hf_hub_download(repo_id="Bingsu/adetailer", filename="deepfashion2_yolov8s-seg.pt")
    yolo_model = YOLO(fashion_model_path) 
    print("Fashion YOLO loaded successfully.")
except Exception as e:
    print(f"Error loading Fashion YOLO: {e}")
    exit(1)

# 4. Meta SAM 3 
print("Loading official Meta SAM 3 model...")
SAM_MODEL_ID = "facebook/sam3" 
try:
    # Bypassing the local cache issue by feeding the token directly
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
    """Step 1: Get fashion-specific bounding boxes and generate an annotated visual."""
    results = yolo_model(image_path, conf=CONF_THRESHOLD, verbose=False)[0]
    
    # YOLO's built-in plotting creates a gorgeous image with boxes and labels (in BGR color space)
    annotated_bgr = results.plot()
    
    # Convert from BGR to RGB so PIL can save it with correct colors
    annotated_rgb = annotated_bgr[..., ::-1]
    annotated_img = Image.fromarray(annotated_rgb)

    items = []
    
    if results.boxes is None:
        return items, annotated_img

    for box in results.boxes:
        # Extract pixel coordinates
        x1, y1, x2, y2 = box.xyxy[0].tolist()
        class_id = int(box.cls[0].item())
        label_name = yolo_model.names[class_id].lower().replace("_", " ")
        
        # Skip if the detected item is just the main product we already have
        if main_product_name and label_name == main_product_name.lower():
            continue  

        items.append({
            "item_name": label_name,
            "bbox": [int(x1), int(y1), int(x2), int(y2)]
        })

    # Return BOTH the math data and the visual image
    return items, annotated_img


def generate_gemini_descriptions(image_path, detected_items):
    """Step 2: Ask Gemini 2.0 Flash to enrich the fashion items YOLO found."""
    if not detected_items:
        return []

    prompt = f"""
    The following items were detected in this image: {[item['item_name'] for item in detected_items]}
    
    For each item, provide:
    1. "category": The best fashion category.
    2. "short_description": A 10-word visual description.
    3. "long_description": A highly detailed 45-word description covering material, style, and fit.

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
                generation_config={"temperature": 0.2, "response_mime_type": "application/json"}
            )
            data = json.loads(response.text)
            
            enriched_items = []
            for yolo_item in detected_items:
                gemini_match = next((g for g in data.get("items", []) if g["item_name"] == yolo_item["item_name"]), {})
                yolo_item["category"] = gemini_match.get("category", yolo_item["item_name"])
                yolo_item["short_description"] = gemini_match.get("short_description", "")
                yolo_item["long_description"] = gemini_match.get("long_description", "")
                enriched_items.append(yolo_item)
                
            return enriched_items

        except Exception as e:
            if "429" in str(e) or "Resource exhausted" in str(e):
                sleep_time = (2 ** attempt) + random.uniform(0, 1)
                print(f"Rate limit hit. Sleeping {sleep_time:.1f}s before retry...")
                time.sleep(sleep_time)
            else:
                print(f"Gemini error: {e}")
                return detected_items
                
    return detected_items


def create_transparent_cutout(image_path, bbox, text_prompt, save_path):
    """Step 3: Official SAM 3 cuts out the item using BOTH text and box prompts."""
    image = Image.open(image_path)
    image = ImageOps.exif_transpose(image).convert("RGB")
    
    # Level 1 (Batch) -> Level 2 (Boxes) -> Level 3 (Coordinates)
    input_boxes = [[bbox]] 
    input_boxes_labels = [[1]] 
    
    # THE MISSING PIECE: We must pass the Gemini text prompt to SAM 3!
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
    # We manually pass (height, width) to bypass Hugging Face dictionary bugs
    results = sam_processor.post_process_instance_segmentation(
        outputs,
        threshold=0.1,  # Lowered slightly to guarantee it grabs the item
        mask_threshold=0.5,
        target_sizes=[(image.height, image.width)]
    )[0]
    
    # Safety check in case SAM 3 still struggles to find the concept
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
    print(img_path)
    
    if not os.path.exists(img_path):
        return product

    print(f"\nProcessing {product_id}...")
    
    # 1. Ultralytics YOLO Detection (Now catches the annotated image too!)
    items, annotated_img = get_yolo_boxes(img_path, product_name)
    print(items)
    
    if not items:
        print(f"  -> No secondary fashion items detected.")
        return product

    # 3. SAM 3 Masking & Saving setup (we moved this up slightly to save the YOLO image)
    product_crop_folder = os.path.join(CROPPED_DIR, product_id)
    os.makedirs(product_crop_folder, exist_ok=True)
    
    # --- NEW: Save the YOLO Annotated Image ---
    annotated_save_path = os.path.join(product_crop_folder, f"{product_id}_yolo_boxes.jpg")
    annotated_img.save(annotated_save_path)
    print(f"  -> Saved YOLO visualization to: {product_id}_yolo_boxes.jpg")

    # 2. Gemini Description Enrichment
    items = generate_gemini_descriptions(img_path, items)

    for item in items:
        try:
            category_safe = item["category"].replace(" ", "_").replace("/", "-")
            save_name = f"{product_id}_{category_safe}.png"
            save_path = os.path.join(product_crop_folder, save_name)
            
            # Feed SAM 3 the image and the exact DeepFashion2 bounding box
            create_transparent_cutout(img_path, item["bbox"], item["short_description"], save_path)
            
            item["cutout_path"] = save_path
            print(f"  -> Successfully extracted transparent PNG: {save_name}")
            
        except Exception as e:
            print(f"  -> Failed to segment {item['item_name']}: {e}")

    product["context_items"] = items
    print(product)
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