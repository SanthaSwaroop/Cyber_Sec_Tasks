#!/usr/bin/env python3
"""
folder_lock.py — Lock (encrypt) and unlock (decrypt) a folder with a password.

Uses only the Python standard library:
  - zipfile  : bundles the folder into a single archive
  - hashlib  : derives an encryption key from your password (PBKDF2-HMAC-SHA256)
  - shutil   : creates/removes files and folders

USAGE
  Lock a folder:
    python folder_lock.py lock "C:\\path\\to\\MyFolder"
    -> creates MyFolder.locked, deletes the original folder

  Unlock it again:
    python folder_lock.py unlock "C:\\path\\to\\MyFolder.locked"
    -> asks for the password, restores MyFolder, deletes the .locked file

You will be prompted for the password (hidden input, not shown on screen or
saved in your shell history).
"""

import argparse
import getpass
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile

try:
    import tkinter as tk
    from tkinter import filedialog
    _TK_AVAILABLE = True
except Exception:
    _TK_AVAILABLE = False

MAGIC = b"PYLOCKv1"      # simple header so we can recognize our own files
SALT_SIZE = 16            # bytes of random salt per lock (prevents rainbow-table reuse)
ITERATIONS = 200_000      # PBKDF2 rounds — slows down password-guessing attacks
CHECKSUM_SIZE = 8         # bytes used to verify the password on unlock


def derive_keystream(password: str, salt: bytes, length: int) -> bytes:
    """Turn a password + salt into `length` bytes of pseudo-random key material."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=length
    )


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypt/decrypt by XOR-ing data with a same-length keystream (symmetric)."""
    return bytes(d ^ k for d, k in zip(data, key))


def lock_folder(folder_path: str, password: str) -> str:
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise NotADirectoryError(f"'{folder_path}' is not a folder.")

    parent = os.path.dirname(folder_path)
    base_name = os.path.basename(folder_path.rstrip(os.sep))

    # 1. Zip the folder into a temporary archive
    with tempfile.TemporaryDirectory() as tmp:
        zip_base = os.path.join(tmp, base_name)
        zip_path = shutil.make_archive(zip_base, "zip", root_dir=parent, base_dir=base_name)
        with open(zip_path, "rb") as f:
            zip_bytes = f.read()

    # 2. Derive a key from the password and encrypt the zip's bytes
    salt = os.urandom(SALT_SIZE)
    keystream = derive_keystream(password, salt, len(zip_bytes))
    encrypted = xor_bytes(zip_bytes, keystream)

    # 3. Store a short checksum of the *original* data so unlock can verify
    #    the password was correct before writing anything to disk.
    checksum = hashlib.sha256(zip_bytes).digest()[:CHECKSUM_SIZE]

    # 4. Write the final .locked file: MAGIC | salt | checksum | encrypted data
    locked_path = folder_path.rstrip(os.sep) + ".locked"
    with open(locked_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(checksum)
        f.write(encrypted)

    # 5. Remove the original, now-unprotected folder
    shutil.rmtree(folder_path)
    return locked_path


def unlock_file(locked_path: str, password: str, output_dir: str = None) -> str:
    locked_path = os.path.abspath(locked_path)
    if not os.path.isfile(locked_path):
        raise FileNotFoundError(f"'{locked_path}' does not exist.")

    with open(locked_path, "rb") as f:
        data = f.read()

    if not data.startswith(MAGIC):
        raise ValueError("This doesn't look like a file created by folder_lock.py.")

    offset = len(MAGIC)
    salt = data[offset: offset + SALT_SIZE]
    offset += SALT_SIZE
    checksum = data[offset: offset + CHECKSUM_SIZE]
    offset += CHECKSUM_SIZE
    encrypted = data[offset:]

    keystream = derive_keystream(password, salt, len(encrypted))
    zip_bytes = xor_bytes(encrypted, keystream)

    if hashlib.sha256(zip_bytes).digest()[:CHECKSUM_SIZE] != checksum:
        raise ValueError("Incorrect password.")

    if output_dir is None:
        output_dir = os.path.dirname(locked_path)

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "restore.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_bytes)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(output_dir)

    os.remove(locked_path)
    restored_name = os.path.basename(locked_path)[: -len(".locked")]
    return os.path.join(output_dir, restored_name)


def pick_folder() -> str:
    """Let the user choose a folder to lock — via a GUI dialog if available,
    otherwise by typing the path."""
    if _TK_AVAILABLE:
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            path = filedialog.askdirectory(title="Select the folder to lock")
            root.destroy()
            if path:
                return path
            print("No folder selected.")
        except Exception:
            pass  # fall back to manual entry below

    path = input("Enter the full path of the folder to lock: ").strip().strip('"')
    return path


def pick_locked_file() -> str:
    """Let the user choose a .locked file to unlock — via a GUI dialog if
    available, otherwise by typing the path."""
    if _TK_AVAILABLE:
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            path = filedialog.askopenfilename(
                title="Select the .locked file to unlock",
                filetypes=[("Locked files", "*.locked"), ("All files", "*.*")],
            )
            root.destroy()
            if path:
                return path
            print("No file selected.")
        except Exception:
            pass  # fall back to manual entry below

    path = input("Enter the full path of the .locked file: ").strip().strip('"')
    return path


def set_new_password() -> str:
    """Prompt twice for a new password, retrying until both entries match."""
    while True:
        password = getpass.getpass("Set a password: ")
        if not password:
            print("Password cannot be empty. Try again.\n")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Try again.\n")
            continue
        print("Password created successfully.")
        return password


def interactive_menu():
    """Simple text menu: Lock / Unlock / Exit, looping until the user exits."""
    print("=== Folder Lock ===")
    while True:
        print("\nWhat would you like to do?")
        print("  1) Lock a folder")
        print("  2) Unlock a folder")
        print("  3) Exit")
        choice = input("Enter 1, 2, or 3: ").strip()

        if choice == "1":
            folder = pick_folder()
            if not folder or not os.path.isdir(folder):
                print(f"Error: '{folder}' is not a valid folder.")
                continue
            password = set_new_password()
            try:
                locked_path = lock_folder(folder, password)
                print(f"Locked -> {locked_path}")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "2":
            locked_file = pick_locked_file()
            if not locked_file or not os.path.isfile(locked_file):
                print(f"Error: '{locked_file}' is not a valid file.")
                continue
            password = getpass.getpass("Password: ")
            try:
                restored_path = unlock_file(locked_file, password)
                print(f"Unlocked -> {restored_path}")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "3":
            print("Goodbye.")
            break

        else:
            print("Please enter 1, 2, or 3.")


def main():
    # No arguments given -> launch the friendly interactive menu instead of
    # requiring CLI flags.
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description="Lock/unlock a folder with a password.")
    sub = parser.add_subparsers(dest="command", required=True)

    lock_p = sub.add_parser("lock", help="Zip and encrypt a folder")
    lock_p.add_argument("folder", help="Path to the folder to lock")

    unlock_p = sub.add_parser("unlock", help="Decrypt and restore a .locked file")
    unlock_p.add_argument("locked_file", help="Path to the .locked file")
    unlock_p.add_argument("--out", help="Where to extract to (default: same location)", default=None)

    args = parser.parse_args()

    try:
        if args.command == "lock":
            password = set_new_password()
            locked_path = lock_folder(args.folder, password)
            print(f"Locked -> {locked_path}")

        elif args.command == "unlock":
            password = getpass.getpass("Password: ")
            restored_path = unlock_file(args.locked_file, password, args.out)
            print(f"Unlocked -> {restored_path}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
