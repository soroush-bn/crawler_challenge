import subprocess
from pathlib import Path

import json


def password_in_image(folder_path: str, image_name: str) -> str:
    image_path = Path(folder_path) / image_name

    if not image_path.exists():
        raise FileNotFoundError(f"No such file: {image_path}")

    prompt = (
    f"You have direct visual access to image files — you can open and see them without any tool, "
    f"script, or command. Do not run any commands (no certutil, no hashing, no PowerShell, no Python, "
    f"no shell of any kind) and do not write any code. This task requires looking at the image only.\n\n"
    f"Open the image file at {image_path.resolve()} and visually look at it. "
    f"Find any text that matches this exact format: VISUALPING{{ followed by sixteen hex characters, "
    f"followed by }}. Example format (not a real answer): VISUALPING{{0000deadbeef0000}}.\n\n"
    f"Respond with ONLY a single valid JSON object, nothing else — no explanation, no markdown code "
    f"fences, no text before or after it. The JSON must have exactly this shape:\n"
    f'{{"password": <string or null>, "reason": <string or null>}}\n\n'
    f"If you find a match: set \"password\" to the exact matching string, and set \"reason\" to a short "
    f"explanation of where in the image it appears and how you identified it (e.g. \"printed in black "
    f"text in the top-left corner\", \"handwritten on a sticky note in the background\").\n\n"
    f"If you do NOT find a match: set both \"password\" and \"reason\" to null. Do not guess, do not "
    f"invent a plausible-looking string, and do not output a password unless you can point to exactly "
    f"where it appears in the image."
    )
    print(f"[AGY] Scanning image: {image_path.resolve()}")
    MODEL="Gemini 3.1 Pro (High)"
    result = subprocess.run(
        ["agy",  "--model", MODEL, "--add-dir", r"E:\projects\visualping\data", "-p", prompt],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(f"agy failed: {result.stderr.strip()}")

    print(f"[AGY] Raw output: {result.stdout.strip()}")
    
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"password": None, "reason": f"failed to parse agy output: {result.stdout.strip()}"}

    # print(f"[AGY] Result: {result.stdout.strip()}")

    # if result.stdout.strip() == "None":
    #     return None
    # else:
    #     return result.stdout.strip()


if __name__ == "__main__":
    password = password_in_image(r"E:\projects\visualping\genai", "field-visit.jpg")
    print(password)