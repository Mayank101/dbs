import json
import requests
import os
import csv
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# --- Configuration ---
BASE_URL = "https://xcdn.next.co.uk/common/items/default/default/itemimages/3_4Ratio/product/lge/{}{}?im=Resize,width=750"
MAX_RETRIES = 4
PARALLEL_RUNS = 8
OUTPUT_DIR = "downloaded_images"
FAILED_CSV = "failed_downloads.csv"
JSON_INPUT_FILE = "prod.json" 

# Ensure the main output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Lock for writing to the CSV safely from multiple threads
csv_lock = Lock()

def log_failure(product_id, url, reason):
    """Logs the final failures to a CSV after all retries are exhausted."""
    with csv_lock:
        with open(FAILED_CSV, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([product_id, url, reason])

def download_image(url, save_path):
    """Attempts to download an image up to MAX_RETRIES times."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, stream=True, timeout=10)
            
            if response.status_code == 200:
                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(1024):
                        f.write(chunk)
                return True, "Success"
            
            elif response.status_code == 404:
                return False, "404_End_Of_Sequence"
            
            else:
                print(f"Server error {response.status_code} for {url}. Retrying ({attempt}/{MAX_RETRIES})...")
                time.sleep(2 ** attempt)

        except requests.RequestException as e:
            print(f"Network error for {url}. Retrying ({attempt}/{MAX_RETRIES})...")
            time.sleep(2 ** attempt)

    return False, "Max retries exhausted"

def process_product(product):
    """Handles the sequential image downloads for a single product."""
    raw_product_id = product.get("product_id")
    if not raw_product_id:
        return

    # Clean the product ID
    clean_id = raw_product_id[:-1] if raw_product_id.lower().endswith('s') else raw_product_id

    # --- NEW: Create a specific directory for this product ---
    product_dir = os.path.join(OUTPUT_DIR, clean_id)
    os.makedirs(product_dir, exist_ok=True)

    i = 1
    while True:
        suffix = "s.jpg" if i == 1 else f"s{i}.jpg"
        url = BASE_URL.format(clean_id, suffix)
        
        # --- NEW: Save the image inside the new product directory ---
        save_path = os.path.join(product_dir, f"{clean_id}_{suffix}")

        success, status = download_image(url, save_path)

        if success:
            i += 1
        elif status == "404_End_Of_Sequence":
            break
        else:
            log_failure(raw_product_id, url, status)
            break

def main():
    with open(FAILED_CSV, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["product_id", "url", "reason"])

    try:
        with open(JSON_INPUT_FILE, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
            print(f"Successfully loaded {len(json_data)} products from {JSON_INPUT_FILE}.")
    except FileNotFoundError:
        print(f"Error: Could not find '{JSON_INPUT_FILE}'.")
        return
    except json.JSONDecodeError:
        print(f"Error: '{JSON_INPUT_FILE}' is not a valid JSON file.")
        return

    print(f"Starting downloads with {PARALLEL_RUNS} parallel workers...")
    with ThreadPoolExecutor(max_workers=PARALLEL_RUNS) as executor:
        executor.map(process_product, json_data)
        
    print(f"\nAll done! Check the '{OUTPUT_DIR}' folder for your structured images.")

if __name__ == "__main__":
    main()