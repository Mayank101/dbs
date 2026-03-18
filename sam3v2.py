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
from transformers import YolosImageProcessor, YolosForObjectDetection
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
OUTPUT_JSON = "prod-sam3-resultsv2.json"
CROPPED_DIR = "boots-sam3-transparentv2" 

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

# ONE BRAIN TO RULE THEM ALL: valentinafeve/yolos-fashionpedia
print("Loading YOLOS Fashionpedia model...")
try:
    yolos_processor = YolosImageProcessor.from_pretrained("valentinafeve/yolos-fashionpedia")
    yolos_model = YolosForObjectDetection.from_pretrained("valentinafeve/yolos-fashionpedia").to(DEVICE)
    print("YOLOS Fashionpedia loaded successfully.")
except Exception as e:
    print(f"Error loading YOLOS: {e}")
    exit(1)

# Meta SAM 3 
print("Loading official Meta SAM 3 model...")
SAM_MODEL_ID = "facebook/sam3" 
sam_processor = Sam3Processor.from_pretrained(SAM_MODEL_ID, token=HF_TOKEN)
sam_model = Sam3Model.from_pretrained(SAM_MODEL_ID, token=HF_TOKEN).to(DEVICE)
sam_model.eval()

print("\nAll systems go! Ready to process.\n" + "-"*40)


# ---------------------------
# PIPELINE FUNCTIONS
# ---------------------------

def get_yolo_boxes(image_path, main_product_name):
    """Step 1: YOLOS Fashionpedia detection for garments and accessories."""
    # Ensure correct orientation so boxes match the image SAM 3 sees
    image = Image.open(image_path)
    image = ImageOps.exif_transpose(image).convert("RGB")
    
    # Process the image for the YOLOS Vision Transformer
    inputs = yolos_processor(images=image, return_tensors="pt").to(DEVICE)
    
    with torch.no_grad():
        outputs = yolos_model(**inputs)
        
    # YOLOS requires us to manually pass the image size to scale the boxes correctly back to the original photo
    target_sizes = torch.tensor([image.size[::-1]]) 
    results = yolos_processor.post_process_object_detection(outputs, threshold=CONF_THRESHOLD, target_sizes=target_sizes)[0]
    
    items = []
    for score, label, box in zip(results["scores"], results["labels"], results["boxes"]):
        # Extract coordinates and label
        x1, y1, x2, y2 = [round(i, 2) for i in box.tolist()]
        label_name = yolos_model.config.id2label[label.item()].lower().replace("_", " ")
        
        # Skip the main product if it matches exactly
        if main_product_name and label_name == main_product_name.lower():
            continue  
            
        items.append({
            "item_name": label_name, 
            "bbox": [int(x1), int(y1), int(x2), int(y2)], 
            "source": "yolos_fashionpedia"
        })

    return items


def generate_gemini_descriptions(image_path, detected_items):
    """Step 2: Ask Gemini 2.0 Flash to act as the final semantic filter."""
    if not detected_items:
        return []

    prompt = f"""
    The following objects were detected in this image: {[item['item_name'] for item in detected_items]}
    
    You are an intelligent Fashion AI. 
    1. Exclude anything that is clearly background noise or human body parts (like 'person', 'face', 'arm', 'wall').
    2. For the VALID fashion items, footwear, and accessories, provide:
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
            
            valid_items = []
            for g_item in data.get("items", []):
                matching_yolo = next((y for y in detected_items if y["item_name"] == g_item["item_name"]), None)
                if matching_yolo:
                    matching_yolo["category"] = g_item.get("category", g_item["item_name"])
                    matching_yolo["short_description"] = g_item.get("short_description", "")
                    matching_yolo["long_description"] = g_item.get("long_description", "")
                    valid_items.append(matching_yolo)
                    
            return valid_items

        except Exception as e:
            if "429" in str(e) or "Resource exhausted" in str(e):
                time.sleep((2 ** attempt) + random.uniform(0, 1))
            else:
                print(f"Gemini error: {e}")
                return []
                
    return []


def create_transparent_cutout(image_path, bbox, text_prompt, save_path):
    """Step 3: SAM 3 cuts out the item."""
    image = Image.open(image_path)
    image = ImageOps.exif_transpose(image).convert("RGB")
    
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

    results = sam_processor.post_process_instance_segmentation(
        outputs,
        threshold=0.1,
        mask_threshold=0.5,
        target_sizes=[(image.height, image.width)]
    )[0]
    
    if len(results["masks"]) == 0:
        raise ValueError(f"SAM 3 returned an empty mask for '{text_prompt}'")
    
    mask_array = results["masks"][0].cpu().numpy()

    image_rgba = image.convert("RGBA")
    alpha_channel = Image.fromarray((mask_array * 255).astype(np.uint8), mode='L')
    
    transparent_img = Image.new("RGBA", image_rgba.size, (0, 0, 0, 0))
    transparent_img.paste(image_rgba, mask=alpha_channel)
    
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
    
    # 1. Single-Brain Fashionpedia YOLO
    raw_items = get_yolo_boxes(img_path, product_name)
    
    # 2. Gemini Final Filter
    clean_items = generate_gemini_descriptions(img_path, raw_items)
    
    if not clean_items:
        print(f"  -> No secondary items detected.")
        return product

    product_crop_folder = os.path.join(CROPPED_DIR, product_id)
    os.makedirs(product_crop_folder, exist_ok=True)

    # 3. Draw Debug Image
    try:
        annotated_img = Image.open(img_path).convert("RGB")
        annotated_img = ImageOps.exif_transpose(annotated_img)
        draw = ImageDraw.Draw(annotated_img)
        
        for item in clean_items:
            x1, y1, x2, y2 = item["bbox"]
            label = item["category"] 
            color = "blue"
            
            draw.rectangle([x1, y1, x2, y2], outline=color, width=4)
            text_bbox = draw.textbbox((x1, y1), label)
            draw.rectangle([text_bbox[0], text_bbox[1], text_bbox[2], text_bbox[3]], fill=color)
            draw.text((x1, y1), label, fill="white")
            
        annotated_save_path = os.path.join(product_crop_folder, f"{product_id}_unified_boxes.jpg")
        annotated_img.save(annotated_save_path)
        print(f"  -> Saved YOLO visualization to: {product_id}_unified_boxes.jpg")
    except Exception as e:
        print(f"  -> Failed to generate debug image: {e}")

    # 4. SAM 3 Masking
    for item in clean_items:
        try:
            category_safe = item["category"].replace(" ", "_").replace("/", "-")
            save_name = f"{product_id}_{category_safe}.png"
            save_path = os.path.join(product_crop_folder, save_name)
            
            create_transparent_cutout(img_path, item["bbox"], item["short_description"], save_path)
            
            item["cutout_path"] = save_path
            print(f"  -> Successfully extracted transparent PNG: {save_name}")
            
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