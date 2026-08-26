import os
import re
from typing import List
from models import ResourceData, Finding

class MediaUtils:
    IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg', '.tiff'}
    DATA_DIR = os.path.join(".", "data")

    @classmethod
    def is_image(cls, resource: ResourceData) -> bool:
        if resource.content_type.lower().startswith("image/"):
            return True
        ext = os.path.splitext(resource.url.split("?")[0])[1].lower()
        return ext in cls.IMAGE_EXTENSIONS


