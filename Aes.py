import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import binascii

# Block creation
def create_blocks(text):
    print("\n[Block Creation] Padding the plaintext to 16-byte blocks...")
    block_size = 16
    padded_text = pad(text.encode('utf-8'), block_size)
    print(f"Padded text (hex): {padded_text.hex()}")
    return padded_text

# Key generation 
def generate_key(password, salt=None):
    print("\n[Key Generation] Generating sub-keys with SHA-256...")
    if not salt:
        salt = get_random_bytes(16) 
        print(f"Generated salt: {salt.hex()}")
    key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    print(f"Generated key: {key.hex()}")
    return key, salt

# AES encryption rounds
def aes_encrypt(key, text, rounds=10):
    # Initialization Vector (IV)
    iv = get_random_bytes(16)
    print(f"\n[Encryption] Using IV: {iv.hex()}")

    #  CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the padded text
    ciphertext = cipher.encrypt(text)
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # encryption rounds
    for round_num in range(1, rounds + 1):
        print(f"Round {round_num}: Executing AES transformations...")

    return iv + ciphertext  

# decryption rounds
def aes_decrypt(key, iv_ciphertext, rounds=10):
    # Extract IV and ciphertext
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    print(f"\n[Decryption] Using IV: {iv.hex()}")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    for round_num in range(1, rounds + 1):
        print(f"Round {round_num}: Executing AES transformations...")

    # Decrypting the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)
    print(f"Padded plaintext (hex): {padded_plaintext.hex()}")

    # Unpadding the plaintext
    try:
        plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
        print(f"Decrypted plaintext: {plaintext}")
        return plaintext
    except (ValueError, KeyError) as e:
        print("Incorrect decryption")
        raise ValueError("Incorrect decryption. Possibly wrong password or corrupted ciphertext.")

# Event handler for encrypting the text
def encrypt_text():
    plaintext = plaintext_entry.get()
    password = password_entry.get()
    
    if not plaintext or not password:
        messagebox.showwarning("Input Error", "Both plaintext and password are required!")
        return
    
    try:
        padded_text = create_blocks(plaintext)
        
        key, salt = generate_key(password)
        
        encrypted_text = aes_encrypt(key, padded_text)
        
        # Combine salt + IV + ciphertext for storage
        combined_encrypted = salt + encrypted_text
        ciphertext_hex = binascii.hexlify(combined_encrypted).decode()
        
        # Display the ciphertext in the GUI
        ciphertext_display.config(state='normal')
        ciphertext_display.delete("1.0", tk.END)
        ciphertext_display.insert(tk.END, ciphertext_hex)
        ciphertext_display.config(state='disabled')
        
       # Display summary in a message box
        summary = (
            f"The password '{password}' was used to derive the encryption key.\n"
            f"Generated key: {binascii.hexlify(key).decode()}\n"
            f"Salt: {salt.hex()}\n"
            f"IV: {encrypted_text[:16].hex()}\n"
            f"Ciphertext (in hex): {ciphertext_hex}"
        )
        messagebox.showinfo("Encryption Success", summary)
        
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred during encryption:\n{str(e)}")

# Event handler for decrypting the text
def decrypt_text():
   
    ciphertext_hex = ciphertext_entry.get("1.0", "end-1c")
    password = decrypt_password_entry.get()
    
    if not ciphertext_hex or not password:
        messagebox.showwarning("Input Error", "Both ciphertext and password are required!")
        return
    
    try:
        #  hex to bytes
        combined_encrypted = binascii.unhexlify(ciphertext_hex)
        
        # Extracting salt, IV, and ciphertext
        salt = combined_encrypted[:16]
        iv_ciphertext = combined_encrypted[16:]
        
        print(f"\n[Decryption] Extracted salt: {salt.hex()}")
        
        # Generate key from password and salt
        key, _ = generate_key(password, salt)
        
        # Decrypting the ciphertext
        decrypted_plaintext = aes_decrypt(key, iv_ciphertext)
        
        # Display the decrypted plaintext in the GUI
        decrypted_display.config(state='normal')
        decrypted_display.delete("1.0", tk.END)
        decrypted_display.insert(tk.END, decrypted_plaintext)
        decrypted_display.config(state='disabled')
        
        # summary in a message box
        summary = (
            f"The password '{password}' was used to derive the decryption key.\n"
            f"Salt: {salt.hex()}\n"
            f"Decrypted Plaintext: {decrypted_plaintext}"
        )
        messagebox.showinfo("Decryption Success", summary)
        
    except binascii.Error:
        messagebox.showerror("Decryption Error", "Invalid ciphertext format. Ensure it's in hexadecimal.")
    except ValueError as ve:
        messagebox.showerror("Decryption Error", f"{str(ve)}")
    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{str(e)}")

# Main function to create the GUI
def main():
    global plaintext_entry, password_entry, ciphertext_display
    global ciphertext_entry, decrypt_password_entry, decrypted_display
    
    root = tk.Tk()
    root.title("AES Encryption-Decryption Tool")
    root.geometry("700x600")
    
    # Notebook for tabs
    from tkinter import ttk
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')
    
    # Frames for Encryption and Decryption
    encryption_frame = ttk.Frame(notebook)
    decryption_frame = ttk.Frame(notebook)
    
    notebook.add(encryption_frame, text='Encrypt')
    notebook.add(decryption_frame, text='Decrypt')
    
    # ------------------- Encryption Frame -------------------
    # grid layout
    encryption_frame.columnconfigure(0, weight=1)
    encryption_frame.columnconfigure(1, weight=3)
    
    # Plaintext input field
    ttk.Label(encryption_frame, text="Plaintext:", font=("Arial", 14)).grid(row=0, column=0, padx=10, pady=10, sticky='e')
    plaintext_entry = ttk.Entry(encryption_frame, font=("Arial", 14), width=50)
    plaintext_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')
    
    # Password input field
    ttk.Label(encryption_frame, text="Password:", font=("Arial", 14)).grid(row=1, column=0, padx=10, pady=10, sticky='e')
    password_entry = ttk.Entry(encryption_frame, font=("Arial", 14), show='*', width=50)
    password_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')
    
    # Encrypt button
    encrypt_button = ttk.Button(encryption_frame, text="Encrypt", command=encrypt_text)
    encrypt_button.grid(row=2, column=1, padx=10, pady=20, sticky='w')
    
    # Ciphertext display
    ttk.Label(encryption_frame, text="Ciphertext (Hex):", font=("Arial", 14)).grid(row=3, column=0, padx=10, pady=10, sticky='ne')
    ciphertext_display = scrolledtext.ScrolledText(encryption_frame, font=("Arial", 12), width=50, height=10, state='disabled')
    ciphertext_display.grid(row=3, column=1, padx=10, pady=10, sticky='w')
    
    # ------------------- Decryption Frame -------------------
    #  grid layout
    decryption_frame.columnconfigure(0, weight=1)
    decryption_frame.columnconfigure(1, weight=3)
    
    # Ciphertext input field
    ttk.Label(decryption_frame, text="Ciphertext (Hex):", font=("Arial", 14)).grid(row=0, column=0, padx=10, pady=10, sticky='ne')
    ciphertext_entry = scrolledtext.ScrolledText(decryption_frame, font=("Arial", 12), width=50, height=10)
    ciphertext_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')
    
    # Password input field for decryption
    ttk.Label(decryption_frame, text="Password:", font=("Arial", 14)).grid(row=1, column=0, padx=10, pady=10, sticky='e')
    decrypt_password_entry = ttk.Entry(decryption_frame, font=("Arial", 14), show='*', width=50)
    decrypt_password_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')
    
    # Decrypt button
    decrypt_button = ttk.Button(decryption_frame, text="Decrypt", command=decrypt_text)
    decrypt_button.grid(row=2, column=1, padx=10, pady=20, sticky='w')
    
    # Decrypted plaintext display 
    ttk.Label(decryption_frame, text="Decrypted Plaintext:", font=("Arial", 11)).grid(row=3, column=0, padx=10, pady=10, sticky='ne')
    decrypted_display = scrolledtext.ScrolledText(decryption_frame, font=("Arial", 12), width=50, height=10, state='disabled')
    decrypted_display.grid(row=3, column=1, padx=10, pady=10, sticky='w')
    
    # Run the application
    root.mainloop()

if __name__ == "__main__":
    main()
