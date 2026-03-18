import json

# 1. Read JSON file (list of dicts)
with open("prod-cleaned.json", "r") as f:
    json_list = json.load(f)

# 2. Your prod_id list
prod_ids = [
    "F93037", "H45913", "V26973", "W99660", "Y14818", "F91098", "V02650", "AR2047", "F35365", "H59422", 
    "H97500", "G12849", "H15766", "G18285", "H92874", "H74816", "W04683", "W90141", "V28359", "F91131", 
    "H14167", "AV0827", "V16904", "V09829", "F70292", "V17837", "Y14702", "H13223", "H86758", "Y10564", 
    "Y29442", "W11003", "V03591", "V22994", "V08415", "V25548", "Y11487", "G15907", "Y02599", "H98720", 
    "H98678", "H86748", "G09702", "V03569", "F34709"
]   # or load from somewhere else

# 3. Convert to set for speed
prod_id_set = set(prod_ids)

# 4. Filter
filtered_list = [
    item for item in json_list 
    if item.get("product_id") in prod_id_set
]

# 5. Save output
with open("filtered_products.json", "w") as f:
    json.dump(filtered_list, f, indent=4)