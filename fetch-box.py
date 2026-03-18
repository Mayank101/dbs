import os
import json
import cv2
import time
import random
import torch
from concurrent.futures import ThreadPoolExecutor
from PIL import Image
from dotenv import load_dotenv
from transformers import AutoImageProcessor, AutoModelForObjectDetection
from huggingface_hub import login

# --- Google Vertex AI Imports ---
from google.oauth2 import service_account
import vertexai
from vertexai.generative_models import GenerativeModel, Part

# Load environment variables (if any are still needed)
load_dotenv()

# --- Initialize Google Vertex AI with Service Account ---
SERVICE_ACCOUNT_FILE = "maven-slikk-search-7179aa0295bc.json"

try:
    # Load credentials from the JSON file
    credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE)
    # Initialize Vertex AI
    vertexai.init(project=credentials.project_id, credentials=credentials)
except Exception as e:
    print(f"Error loading service account: {e}")
    print("Please make sure 'service_account.json' is in the same directory.")
    exit(1)

# Initialize Gemini 2.0 Flash (Update this string if a newer version is required)
gemini_model = GenerativeModel("gemini-2.5-flash")

# --- Configuration ---
DATASET_DIR = "downloaded_images"
PRODUCT_JSON = "prod-cleaned.json"
OUTPUT_FILE = "prod-all-crop-results.json"
OUTPUT_DIR = "prod-all-crop"
CROPPED_DIR = "prod-all-sample-next"

# Note: If you still get massive amounts of 429 errors even with the retries, 
# lower this number to 3 or 4 to ease the load on the API.
MAX_WORKERS = 8 
CONF_THRESHOLD = 0.3

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CROPPED_DIR, exist_ok=True)

# HuggingFace Login
# Replace "your key" with your actual key, or use os.getenv("HF_TOKEN") if in .env
login(token="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")  

# Initialize YOLO Model
MODEL_NAME = "yainage90/fashion-object-detection"
print("Loading YOLO model...")
processor = AutoImageProcessor.from_pretrained(MODEL_NAME)
model = AutoModelForObjectDetection.from_pretrained(MODEL_NAME)
model.eval()
print("YOLO model loaded successfully.")

# Load Products
try:
    with open(PRODUCT_JSON, 'r', encoding='utf-8') as f:
        products_json = json.load(f)
except FileNotFoundError:
    print(f"Error: Could not find '{PRODUCT_JSON}'. Please check the filename.")
    exit(1)

# Extract Categories dynamically from the JSON
all_categories_set = set()
for product in products_json:
    if "category" in product:
        all_categories_set.add(product["category"].lower())
    elif "productName" in product:
        all_categories_set.add(product["productName"].lower())
ALL_CATEGORIES = list(all_categories_set)


def call_gemini(prompt, image_path, max_retries=6):
    """Calls Gemini 2.0 Flash with Exponential Backoff to handle 429 Quota errors."""
    with open(image_path, "rb") as f:
        image_bytes = f.read()

    image_part = Part.from_data(data=image_bytes, mime_type="image/jpeg")

    for attempt in range(max_retries):
        try:
            response = gemini_model.generate_content(
                [image_part, prompt],
                generation_config={
                    "temperature": 0.2,
                    "response_mime_type": "application/json",
                }
            )
            return json.loads(response.text)
            
        except Exception as e:
            error_msg = str(e)
            # Check if it's a rate limit / quota error (429)
            if "429" in error_msg or "Resource exhausted" in error_msg:
                # Calculate sleep time: 2, 4, 8, 16, 32 seconds + a random fraction of a second (jitter)
                sleep_time = (2 ** attempt) + random.uniform(0, 1)
                print(f"Rate limit hit. Sleeping for {sleep_time:.1f}s before retrying {os.path.basename(image_path)}... (Attempt {attempt+1}/{max_retries})")
                time.sleep(sleep_time)
            else:
                # If it's a different error (like a corrupted image), print it and give up
                print(f"Gemini API error for {image_path}: {e}")
                return {}
                
    print(f"Failed to process {image_path} after {max_retries} attempts due to rate limits. Skipping.")
    return {}


def detect_items_yolo(image_path, main_product_name):
    """Uses YOLO to find bounding boxes, ignoring the main product."""
    image = Image.open(image_path).convert("RGB")
    width, height = image.size
    inputs = processor(images=image, return_tensors="pt")

    with torch.no_grad():
        outputs = model(**inputs)

    target_sizes = torch.tensor([[height, width]])
    results = processor.post_process_object_detection(
        outputs, threshold=CONF_THRESHOLD, target_sizes=target_sizes
    )[0]

    items = []
    for score, label, box in zip(results["scores"], results["labels"], results["boxes"]):
        label_name = model.config.id2label[label.item()].lower()
        
        # Skip the main product itself
        if main_product_name and label_name == main_product_name.lower():
            continue  

        x1, y1, x2, y2 = box.tolist()
        bbox = [x1 / width, y1 / height, x2 / width, y2 / height]

        items.append({
            "item_name": label_name,
            "bounding_box": bbox,
            "long_description": "",
            "category": ""
        })

    return items


def generate_long_descriptions_with_category(image_path, items, all_categories):
    """Asks Gemini to describe and categorize the secondary items found by YOLO."""
    if not items:
        return items

    prompt = f"""
    These items are visible in the image: {json.dumps(items)}

    For each item:
    1. Generate a detailed long description including color, material, texture, style, and design details.
    2. Pick the most appropriate category for this item from the following list: {all_categories}.
    3. Keep each description short, no more than 45 words.

    Return JSON strictly in this format:
    {{
        "items": [
            {{"item_name": "", "long_description": "", "category": ""}}
        ]
    }}
    """
    result = call_gemini(prompt, image_path)
    descriptions = result.get("items", [])

    for item, desc in zip(items, descriptions):
        item["long_description"] = desc.get("long_description", "")
        item["category"] = desc.get("category", "")

    return items


def main_product_description(image_path, product_name):
    """Asks Gemini to describe the main product in detail."""
    prompt = f"""
    This image shows the product "{product_name}".
    Write a detailed long description including: color, material, fabric, texture, stitching, design elements, fit, pattern, and style category.
    Keep each description short, no more than 45 words.
    
    Return JSON strictly in this format: {{"description": ""}}
    """
    result = call_gemini(prompt, image_path)
    return result.get("description", "")


def process_image(product_name, image_path, is_first_image):
    """Routes the image to the correct pipeline based on its position."""
    filename = os.path.basename(image_path)
    if is_first_image:
        items = detect_items_yolo(image_path, product_name)
        items = generate_long_descriptions_with_category(image_path, items, ALL_CATEGORIES)
        return {
            "image": filename,
            "type": "context_detection",
            "items": items
        }
    else:
        description = main_product_description(image_path, product_name)
        return {
            "image": filename,
            "type": "product_description",
            "description": description
        }


def process_product(product):
    """Processes all images for a single product concurrently, with timing."""
    start_time = time.time()
    
    product_id = product.get("product_id")
    product_name = product.get("productName", "")
    folder = os.path.join(DATASET_DIR, product_id)

    result = {"product_id": product_id, "product_name": product_name, "images": []}
    
    if not os.path.exists(folder):
        print(f"[{product_id}] Skipped: No image folder found.")
        return result

    # Find all JPG images in the product folder
    images = sorted([os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith(".jpg")])
    
    if not images:
        print(f"[{product_id}] Skipped: Folder exists but is empty.")
        return result

    # Run the image processing in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        outputs = list(executor.map(
            lambda idx_img: process_image(product_name, idx_img[1], idx_img[0]==0),
            enumerate(images)
        ))
        
    result["images"] = outputs
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"[{product_id}] Processed {len(images)} images in {elapsed_time:.2f} seconds")
    
    return result


def draw_boxes():
    """Draws green bounding boxes on the original images for visual verification."""
    print("\nDrawing bounding boxes...")
    try:
        with open(OUTPUT_FILE) as f:
            data = json.load(f)
    except FileNotFoundError:
        return

    for product in data:
        product_id = product.get("product_id")
        folder = os.path.join(DATASET_DIR, product_id)

        for img_data in product.get("images", []):
            if img_data.get("type") != "context_detection":
                continue

            image_name = img_data.get("image")
            image_path = os.path.join(folder, image_name)
            if not os.path.exists(image_path):
                continue

            image = cv2.imread(image_path)
            if image is None:
                continue
                
            h, w, _ = image.shape

            for item in img_data.get("items", []):
                bbox = item.get("bounding_box", [])
                if len(bbox) != 4:
                    continue
                    
                x1, y1, x2, y2 = int(bbox[0]*w), int(bbox[1]*h), int(bbox[2]*w), int(bbox[3]*h)
                label = f"{item.get('category', item.get('item_name'))}"
                cv2.rectangle(image, (x1, y1), (x2, y2), (0,255,0), 2)
                cv2.putText(image, label, (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,255,0), 2)

            save_path = os.path.join(OUTPUT_DIR, f"{product_id}_{image_name}")
            cv2.imwrite(save_path, image)
            print(f"Saved annotated image: {save_path}")


def crop_items_and_update_json():
    """Crops the secondary items out into small PNGs and updates the JSON paths."""
    print("\nCropping items...")
    try:
        with open(OUTPUT_FILE) as f:
            data = json.load(f)
    except FileNotFoundError:
        return

    for product in data:
        product_id = product.get("product_id")
        folder = os.path.join(DATASET_DIR, product_id)
        if not os.path.exists(folder):
            continue

        product_output_folder = os.path.join(CROPPED_DIR, product_id)
        os.makedirs(product_output_folder, exist_ok=True)

        for img_data in product.get("images", []):
            if img_data.get("type") != "context_detection":
                continue

            image_name = img_data.get("image")
            image_path = os.path.join(folder, image_name)
            if not os.path.exists(image_path):
                continue

            try:
                image = Image.open(image_path).convert("RGB")
                width, height = image.size

                for item in img_data.get("items", []):
                    bbox = item.get("bounding_box", [])
                    if len(bbox) != 4:
                        continue

                    x_min = int(bbox[0] * width)
                    y_min = int(bbox[1] * height)
                    x_max = int(bbox[2] * width)
                    y_max = int(bbox[3] * height)

                    cropped = image.crop((x_min, y_min, x_max, y_max))
                    category_safe = item.get("category", item.get("item_name", "item")).replace(" ", "_").replace("/", "-")
                    save_name = f"{image_name}_{category_safe}.png"
                    save_path = os.path.join(product_output_folder, save_name)
                    
                    cropped.save(save_path)
                    print(f"Saved cropped item: {save_path}")

                    # Update JSON with the path to the newly cropped image
                    item["cropped_image_path"] = save_path

            except Exception as e:
                print(f"Failed to crop {image_path}: {e}")

    # Save the updated JSON with all the cropped image paths included
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)


def main():
    """Runs the main processing pipeline."""
    total_start_time = time.time()
    
    results = []
    print(f"\n--- Starting AI Pipeline for {len(products_json)} products ---")
    
    for product in products_json:
        res = process_product(product)
        results.append(res)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    total_end_time = time.time()
    total_elapsed = total_end_time - total_start_time
    minutes = int(total_elapsed // 60)
    seconds = int(total_elapsed % 60)

    print(f"\n--- Processing Complete ---")
    print(f"Total time taken: {minutes} minutes and {seconds} seconds.")
    print(f"Raw output saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
    draw_boxes()
    crop_items_and_update_json()
    print("\nAll tasks finished successfully!")