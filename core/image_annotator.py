import cv2
import numpy as np
import logging
from pathlib import Path
from typing import List, Dict, Any
from config import CATEGORY_COLORS_BGR, SCREENSHOTS_DIR

logger = logging.getLogger(__name__)

class ImageAnnotator:
    """Step 8 & 9: Draws color-coded bounding boxes and labels directly onto evidence screenshots using OpenCV."""

    @staticmethod
    def annotate_and_save_screenshot(
        raw_image_bytes: bytes, 
        output_filename: str, 
        keyword_findings: List[Dict[str, Any]], 
        payment_findings: List[Dict[str, Any]]
    ) -> str:
        """
        Reads raw screenshot image bytes, overlays color-coded bounding boxes 
        for all discovered keywords and payment elements, saves the single 
        highlighted evidence image, and returns the file path.
        """
        output_path = SCREENSHOTS_DIR / output_filename

        # Convert raw bytes to OpenCV image array
        nparr = np.frombuffer(raw_image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            logger.error("Failed to decode image bytes with OpenCV")
            # Save raw bytes if OpenCV fails
            with open(output_path, "wb") as f:
                f.write(raw_image_bytes)
            return str(output_path)

        img_h, img_w = img.shape[:2]

        # 1. Draw Bounding Boxes for Keyword Findings
        for item in keyword_findings:
            bbox = item.get("bounding_box")
            if not bbox or not isinstance(bbox, dict):
                continue
            
            x = int(bbox.get("x", 0))
            y = int(bbox.get("y", 0))
            w = int(bbox.get("width", 0))
            h = int(bbox.get("height", 0))

            if w <= 0 or h <= 0:
                continue

            # Ensure box fits within image bounds
            x1 = max(0, min(x, img_w - 1))
            y1 = max(0, min(y, img_h - 1))
            x2 = max(0, min(x + w, img_w - 1))
            y2 = max(0, min(y + h, img_h - 1))

            cat = item.get("category", "Financial")
            color = CATEGORY_COLORS_BGR.get(cat, (0, 255, 0)) # Default green

            # Draw clean rectangle outline (Thickness 2)
            cv2.rectangle(img, (x1, y1), (x2, y2), color, 2)

        # 2. Draw Bounding Boxes for Payment Findings (QR Codes, Gateway Elements)
        for item in payment_findings:
            bbox = item.get("bounding_box")
            if not bbox or not isinstance(bbox, dict):
                continue
            
            x = int(bbox.get("x", 0))
            y = int(bbox.get("y", 0))
            w = int(bbox.get("width", 0))
            h = int(bbox.get("height", 0))

            if w <= 0 or h <= 0:
                continue

            x1 = max(0, min(x, img_w - 1))
            y1 = max(0, min(y, img_h - 1))
            x2 = max(0, min(x + w, img_w - 1))
            y2 = max(0, min(y + h, img_h - 1))

            color = CATEGORY_COLORS_BGR.get("Payment_Indicator", (0, 0, 255)) # Bright Red
            # Draw clean payment rectangle outline (Thickness 3)
            cv2.rectangle(img, (x1, y1), (x2, y2), color, 3)

        # Save highlighted image
        cv2.imwrite(str(output_path), img)
        return str(output_path)
