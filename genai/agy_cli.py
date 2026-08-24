import subprocess
from pathlib import Path


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
        f"Respond with ONLY the matching password if you see one, or the single word None if you do not. "
        f"No explanation, no quotes, no extra text, no formatting — output must be exactly the password or "
        f"exactly the word None and nothing else."
    )

    print(f"[AGY] Scanning image: {image_path.resolve()}")

    result = subprocess.run(
        ["agy", "--add-dir", r"E:\projects\visualping\data", "-p", prompt],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        print(f"[AGY] Failed with return code {result.returncode}: {result.stderr.strip()}")
        raise RuntimeError(f"agy failed: {result.stderr.strip()}")

    print(f"[AGY] Result: {result.stdout.strip()}")

    if result.stdout.strip() == "None":
        return None
    else:
        return result.stdout.strip()


if __name__ == "__main__":
    password = password_in_image(r"E:\projects\visualping\genai", "field-visit.jpg")
    print(password)