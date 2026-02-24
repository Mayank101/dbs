from transformers import Sam3Processor, Sam3Model
from PIL import Image
import torch
import requests
import numpy as np
import os

device = "cuda" if torch.cuda.is_available() else "cpu"

# FIX: Use Sam3Processor specifically for the sam3 weights
try:
    processor = Sam3Processor.from_pretrained("facebook/sam3")
    model = Sam3Model.from_pretrained("facebook/sam3").to(device)
    print("SAM 3 successfully loaded!")
except Exception as e:
    print(f"Error loading SAM 3: {e}")
    print("Ensure you have accepted the license on Hugging Face and ran 'huggingface-cli login'.")

image_path = "H98720s.jpg.webp"
image = Image.open(image_path).convert("RGB")
image_np = np.array(image)
orig_h, orig_w = image_np.shape[:2]

# 3. Define what you want to extract separately
# SAM 3 works best with short noun phrases (average 15.3 words)
items_to_extract = ["trousers", "shirt", "shoes", "face"]

def get_segmented_item(item_name):
    # Process for the specific item
    inputs = processor(images=image, text=item_name, return_tensors="pt").to(device)

    with torch.no_grad():
        outputs = model(
            pixel_values=inputs.get("pixel_values"),
            input_ids=inputs.get("input_ids"),
            return_dict=True
        )

    # Post-process to original image size
    results = processor.post_process_instance_segmentation(
        outputs,
        threshold=0.5,
        target_sizes=[(orig_h, orig_w)]
    )[0]

    if len(results["masks"]) == 0:
        print(f"No {item_name} detected.")
        return None

    # Merge masks if the model found multiple parts (e.g., left and right shoe)
    combined_mask = np.zeros((orig_h, orig_w), dtype=bool)
    for mask in results["masks"]:
        combined_mask = combined_mask | mask.cpu().numpy().astype(bool)

    # Apply mask to create a transparent background image
    # We use 4 channels (RGBA) so the background is invisible
    rgba_image = np.zeros((orig_h, orig_w, 4), dtype=np.uint8)
    rgba_image[:, :, :3] = image_np  # RGB channels
    rgba_image[:, :, 3] = combined_mask.astype(np.uint8) * 255  # Alpha channel

    return Image.fromarray(rgba_image)

# 4. Run loop and save each item
if not os.path.exists("extracted_items"):
    os.makedirs("extracted_items")

for item in items_to_extract:
    result_img = get_segmented_item(item)
    if result_img:
        save_path = f"extracted_items/{item}.png"
        result_img.save(save_path)
        print(f"Saved: {save_path}")

print("\nAll items (excluding the coat) have been extracted separately.")
