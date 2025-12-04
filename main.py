import argparse
import os
import secrets
import shutil
import qrcode
import concurrent.futures
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def shred_file(path, passes=3):
    try:
        if not os.path.isfile(path):
            return
        size = os.path.getsize(path)
        with open(path, "wb") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
        new = path + ".del"
        os.rename(path, new)
        os.remove(new)
    except Exception:
        pass

def shred_folder(path):
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            shred_file(os.path.join(root, f))
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except Exception:
                pass
    try:
        os.rmdir(path)
    except Exception:
        pass

def clean_metadata(path):
    try:
        os.utime(path, (0, 0))
        os.chmod(path, 0o600)
    except Exception:
        pass

def encrypt_single_file(input_path, output_dir, extension):
    clean_metadata(input_path)
    with open(input_path, "rb") as f:
        data = f.read()
    ext = os.path.splitext(input_path)[1].encode()
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    enc = aes.encrypt(nonce, ext + b"::" + data, None)
    name = secrets.token_hex(16) + extension
    out = os.path.join(output_dir, name)
    with open(out, "wb") as f:
        f.write(nonce + enc)
    qrcode.make(key.hex()).save(out + "_key.png")
    shred_file(input_path)
    print("[✔] File encrypted:", out)
    print("[!] Key:", key.hex())
    print("[>] QR saved:", out + "_key.png")
    return out

def encrypt_file_with_master(input_path, output_dir, extension, key):
    clean_metadata(input_path)
    with open(input_path, "rb") as f:
        data = f.read()
    ext = os.path.splitext(input_path)[1].encode()
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    enc = aes.encrypt(nonce, ext + b"::" + data, None)
    name = secrets.token_hex(16) + extension
    out = os.path.join(output_dir, name)
    with open(out, "wb") as f:
        f.write(nonce + enc)
    return out

def encrypt_folder(folder_path, output_dir, extension):
    if not os.path.isdir(folder_path):
        print("[ERROR] Not a folder.")
        return

    key = AESGCM.generate_key(bit_length=256)
    session = os.path.join(output_dir, secrets.token_hex(8))
    os.makedirs(session, exist_ok=True)

    qrcode.make(key.hex()).save(session + "_masterkey.png")

    files = []
    for root, _, fs in os.walk(folder_path):
        for f in fs:
            src = os.path.join(root, f)
            rel = os.path.relpath(root, folder_path)
            outdir = os.path.join(session, rel)
            os.makedirs(outdir, exist_ok=True)
            files.append((src, outdir))

    try:
        with Progress(
            TextColumn("[bold blue]Encrypting Folder"),
            BarColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ) as p:
            task = p.add_task("encrypt", total=len(files))

            def work(x):
                src, outdir = x
                r = encrypt_file_with_master(src, outdir, extension, key)
                p.update(task, advance=1)
                return r

            with concurrent.futures.ThreadPoolExecutor() as pool:
                futures = [pool.submit(work, x) for x in files]
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()

    except Exception as e:
        print("[ERROR] Failed:", e)
        shutil.rmtree(session, ignore_errors=True)
        return

    shred_folder(folder_path)

    print("[✔] Folder encrypted:", session)
    print("[!] Master Key:", key.hex())
    print("[>] QR saved:", session + "_masterkey.png")

def decrypt_file_with_key(path, key, outdir):
    aes = AESGCM(key)
    with open(path, "rb") as f:
        d = f.read()
    nonce = d[:12]
    enc = d[12:]
    dec = aes.decrypt(nonce, enc, None)
    ext, content = dec.split(b"::", 1)
    ext = ext.decode()
    name = secrets.token_hex(16) + ext
    out = os.path.join(outdir, name)
    with open(out, "wb") as f:
        f.write(content)
    return out

def decrypt_folder(folder_path, key_hex, output_dir):
    if not os.path.isdir(folder_path):
        print("[ERROR] Not a folder.")
        return

    key = bytes.fromhex(key_hex)
    files = []

    for root, _, fs in os.walk(folder_path):
        for f in fs:
            if f.endswith(".vault"):
                src = os.path.join(root, f)
                rel = os.path.relpath(root, folder_path)
                outdir = os.path.join(output_dir, rel)
                os.makedirs(outdir, exist_ok=True)
                files.append((src, outdir))

    try:
        with Progress(
            TextColumn("[bold green]Decrypting Folder"),
            BarColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ) as p:
            task = p.add_task("decrypt", total=len(files))

            def work(x):
                src, out = x
                r = decrypt_file_with_key(src, key, out)
                p.update(task, advance=1)
                return r

            with concurrent.futures.ThreadPoolExecutor() as pool:
                futures = [pool.submit(work, x) for x in files]
                for f in concurrent.futures.as_completed(futures):
                    f.result()

    except Exception as e:
        print("[ERROR] Decryption failed:", e)
        return

    print("[✔] Folder decrypted.")

def decrypt_single(path, key_hex, outdir):
    try:
        key = bytes.fromhex(key_hex)
        decrypt_file_with_key(path, key, outdir)
        print("[✔] File decrypted.")
    except Exception as e:
        print("[ERROR]", e)

def shred_only(path):
    if os.path.isfile(path):
        shred_file(path)
        print("[✔] File shredded.")
    elif os.path.isdir(path):
        shred_folder(path)
        print("[✔] Folder shredded.")
    else:
        print("[ERROR] Not found.")

def main():
    p = argparse.ArgumentParser(description="FileCrypt - Secure File Encryption in Python")
    sub = p.add_subparsers(dest="cmd")

    e = sub.add_parser("encrypt")
    e.add_argument("file")
    e.add_argument("-o", "--output", default=".")
    e.add_argument("-ext", "--extension", default=".vault")

    ef = sub.add_parser("encrypt-folder")
    ef.add_argument("folder")
    ef.add_argument("-o", "--output", default=".")
    ef.add_argument("-ext", "--extension", default=".vault")

    d = sub.add_parser("decrypt")
    d.add_argument("file")
    d.add_argument("key")
    d.add_argument("-o", "--output", default=".")

    df = sub.add_parser("decrypt-folder")
    df.add_argument("folder")
    df.add_argument("key")
    df.add_argument("-o", "--output", default=".")

    s = sub.add_parser("shred")
    s.add_argument("path")

    args = p.parse_args()

    if args.cmd == "encrypt":
        encrypt_single_file(args.file, args.output, args.extension)
    elif args.cmd == "encrypt-folder":
        encrypt_folder(args.folder, args.output, args.extension)
    elif args.cmd == "decrypt":
        decrypt_single(args.file, args.key, args.output)
    elif args.cmd == "decrypt-folder":
        decrypt_folder(args.folder, args.key, args.output)
    elif args.cmd == "shred":
        shred_only(args.path)
    else:
        p.print_help()

if __name__ == "__main__":
    main()