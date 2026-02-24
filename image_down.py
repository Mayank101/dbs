import requests
from io import BytesIO
from PIL import Image
from google import genai

# 1. Initialize Gemini Client (Vertex AI)
client = genai.Client(
    vertexai=True, 
    project='your-gcp-project-id', 
    location='us-central1',
    credentials='service-account.json'
)

# 2. Download function for your loop
def get_image_from_url(url):
    response = requests.get(url, stream=True)
    response.raise_for_status() # Check for download errors
    return Image.open(BytesIO(response.content)).convert("RGB")

# 3. Running the discovery
# Replace this with your loop logic
url = "https://your-fashion-image-url.jpg"
image = get_image_from_url(url)

# Call Gemini: pass the image object directly in the list
response = client.models.generate_content(
    model="gemini-2.0-flash", 
    contents=[
        image, 
        "Identify every clothing item except the coat. Return a comma-separated list."
    ]
)

print(f"Items found: {response.text}")
