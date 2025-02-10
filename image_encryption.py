from PIL import Image
import os
from typing import Tuple

def xor_crypt_image(input_path: str, output_path: str, key: str) -> bool:
    """
    Encrypt/decrypt an image using XOR operation with a cyclic key.
    Supports RGB, RGBA, and other common image modes.
    """
    try:
        # Validate the input file exists.
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Ensure the output directory exists.
        output_dir = os.path.dirname(output_path) or os.getcwd()
        os.makedirs(output_dir, exist_ok=True)

        # Open the image and record its original mode.
        with Image.open(input_path) as img:
            original_mode = img.mode
            # Convert to RGBA to uniformly process transparency, etc.
            img = img.convert("RGBA")
            pixels = img.load()
            width, height = img.size

            # Validate and prepare the key.
            if not key:
                raise ValueError("Encryption key cannot be empty")
            key_bytes = key.encode("utf-8")
            key_len = len(key_bytes)

            # Process each pixel; only the RGB channels are XOR'ed.
            key_index = 0
            for y in range(height):
                for x in range(width):
                    pixel = list(pixels[x, y])
                    for i in range(3):  # Process only the first three channels (RGB)
                        pixel[i] ^= key_bytes[key_index % key_len]
                        key_index += 1
                    pixels[x, y] = tuple(pixel)

            # Determine the file extension from the output path.
            ext = os.path.splitext(output_path)[1].lower()
            if not ext:
                raise ValueError("Output file path must have a valid extension (e.g., .png, .jpg).")
            ext = ext[1:]  # remove the dot

            # Define supported formats.
            supported_formats = ['png', 'jpg', 'jpeg', 'bmp']
            if ext not in supported_formats:
                raise ValueError(f"Unsupported file format: .{ext}. Supported formats: {supported_formats}")

            # For JPEG, convert to 'RGB' since JPEG doesn't support transparency.
            if ext in ['jpg', 'jpeg'] and original_mode in ['RGBA', 'LA']:
                save_mode = 'RGB'
            else:
                save_mode = original_mode

            # Save the image using the extension-derived format.
            img.convert(save_mode).save(output_path, format=ext.upper())
            return True

    except Exception as e:
        print(f"\n⚠️ Error: {str(e)}")
        return False

def get_valid_input(prompt: str, validator: callable) -> str:
    """Get validated user input with error handling."""
    while True:
        try:
            value = input(prompt).strip()
            if validator(value):
                return value
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            exit()
        except Exception as e:
            print(f"Invalid input: {str(e)}")

def main_menu():
    """Interactive terminal interface."""
    print("\n" + "═" * 50)
    print("🔐 Image Cryptor - XOR Encryption/Decryption Tool")
    print("═" * 50)
    
    while True:
        print("\nMain Options:")
        print("1. Encrypt Image")
        print("2. Decrypt Image")
        print("3. Exit")
        
        choice = get_valid_input(
            "\nChoose action (1-3): ",
            lambda x: x in {"1", "2", "3"}
        )

        if choice == "3":
            print("\nGoodbye! 👋")
            break

        # Get operation parameters.
        print("\n" + "─" * 50)
        input_path = get_valid_input(
            "Input image path: ",
            lambda p: os.path.exists(p.strip())
        )
        output_path = get_valid_input(
            "Output image path (include extension, e.g., output.png): ",
            lambda p: bool(p.strip())
        )
        key = get_valid_input(
            "Encryption/decryption key: ",
            lambda k: bool(k.strip())
        )

        # Process the image.
        print("\n🔧 Processing...", end="", flush=True)
        success = xor_crypt_image(input_path, output_path, key)
        
        if success:
            print("\r✅ Operation completed successfully!")
            print(f"   Output saved to: {os.path.abspath(output_path)}")
        else:
            print("\r❌ Operation failed. See error details above.")

        # Ask if the user wants to perform another operation.
        if input("\nPerform another operation? (y/n): ").lower() != "y":
            print("\nGoodbye! 👋")
            break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user. Exiting...")
