import json

# --- Configuration ---
INPUT_JSON = "prod.json"         # The file you want to clean
OUTPUT_JSON = "prod-cleaned.json"     # Where to save the fixed version

def remove_duplicates():
    # 1. Load the data safely handling special characters
    try:
        with open(INPUT_JSON, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find '{INPUT_JSON}'")
        return

    seen_ids = set()
    cleaned_data = []

    # 2. Loop through the products and filter duplicates
    for product in data:
        product_id = product.get("product_id")
        
        # If the product doesn't have an ID (bad data), or we already saw it, skip it
        if not product_id or product_id in seen_ids:
            continue
            
        # Otherwise, add it to our "seen" list and keep the product
        seen_ids.add(product_id)
        cleaned_data.append(product)

    # 3. Save the cleaned data back to a new JSON file
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        # ensure_ascii=False prevents symbols like Â£ from turning into ugly unicode \u00A3
        json.dump(cleaned_data, f, indent=2, ensure_ascii=False)

    # 4. Print out the results so you know exactly what happened
    original_count = len(data)
    new_count = len(cleaned_data)
    duplicates_removed = original_count - new_count
    
    print(f"Original product count: {original_count}")
    print(f"Cleaned product count:  {new_count}")
    print(f"Total duplicates removed: {duplicates_removed}")
    print(f"Saved cleanly to '{OUTPUT_JSON}'")

if __name__ == "__main__":
    remove_duplicates()