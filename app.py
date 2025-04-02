import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, Toplevel, Label, Entry, Text, Button
import tkinter.ttk  # For Notebook tabs
import gnupg
import os
import requests
import urllib.parse
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import configparser
import threading
import socket  # Added for P2P networking

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('gpg_app')

# Setup GPG
try:
    gpg = gnupg.GPG()
except Exception as e:
    messagebox.showerror("GPG Error", f"Failed to initialize GPG: {e}")
    # Optionally, exit or disable GPG features here
    raise SystemExit

# SMTP Config
def load_smtp_config():
    config = configparser.ConfigParser()
    config_file = 'mail_config.ini'
    
    if os.path.exists(config_file):
        config.read(config_file)
        return {
            'server': config.get('SMTP', 'server', fallback=''),
            'port': config.getint('SMTP', 'port', fallback=587),
            'username': config.get('SMTP', 'username', fallback=''),
            'password': config.get('SMTP', 'password', fallback=''),
            'use_tls': config.getboolean('SMTP', 'use_tls', fallback=True)
        }
    else:
        config['SMTP'] = {
            'server': '',
            'port': '587',
            'username': '',
            'password': '',
            'use_tls': 'True'
        }
        with open(config_file, 'w') as f:
            config.write(f)
        return load_smtp_config()

# GUI App
class GPGApp:
    def __init__(self, master):
        self.master = master
        master.title("chatGPG - Encrypted P2P Chat and Mailing")
        master.geometry("800x700")  # Increased size to accommodate chat
        
        # Load SMTP configuration
        self.smtp_config = load_smtp_config()

        # Create notebook for tabs
        self.notebook = tk.ttk.Notebook(master)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Encryption/Decryption Tab
        self.main_frame = tk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text='Encrypt/Decrypt')

        # Chat Tab
        self.chat_frame = tk.Frame(self.notebook)
        self.notebook.add(self.chat_frame, text='P2P Chat')

        # Setup main tab
        self.setup_main_interface()
        # Setup chat tab
        self.setup_chat_interface()

        # Socket variables for P2P chat
        self.server_socket = None
        self.client_socket = None
        self.chat_active = False

    # ----------------------- Main Interface -----------------------
    def setup_main_interface(self):
        # Recipient Label
        self.label_recipient = tk.Label(self.main_frame, text="Recipient Email:")
        self.label_recipient.pack(pady=5)

        # Recipient Entry
        self.entry_recipient = tk.ttk.Combobox(self.main_frame, width=50)
        self.entry_recipient['values'] = self.get_public_key_emails()
        self.entry_recipient.pack(pady=5)

        # Add keyring note
        keyring_note = tk.Label(self.main_frame, text="Note: This application uses your system's default GPG keyring (e.g., ~/.gnupg).")
        keyring_note.pack(pady=5)

        # Text Area Label
        self.label_text = tk.Label(self.main_frame, text="Text Input/Output:")
        self.label_text.pack(pady=5)

        # Text Area
        self.text_area = scrolledtext.ScrolledText(self.main_frame, width=70, height=15)
        self.text_area.pack(pady=5)

        # Buttons Frame for Encryption/Decryption
        self.frame_buttons = tk.Frame(self.main_frame)
        self.frame_buttons.pack(pady=10)

        self.button_encrypt_text = tk.Button(self.frame_buttons, text="Encrypt Text", command=self.encrypt_text)
        self.button_encrypt_text.grid(row=0, column=0, padx=5)

        self.button_decrypt_text = tk.Button(self.frame_buttons, text="Decrypt Text", command=self.decrypt_text)
        self.button_decrypt_text.grid(row=0, column=1, padx=5)

        self.button_encrypt_file = tk.Button(self.frame_buttons, text="Encrypt File", command=self.encrypt_file)
        self.button_encrypt_file.grid(row=0, column=2, padx=5)

        self.button_decrypt_file = tk.Button(self.frame_buttons, text="Decrypt File", command=self.decrypt_file)
        self.button_decrypt_file.grid(row=0, column=3, padx=5)
        
        # Email buttons
        self.frame_email_buttons = tk.Frame(self.main_frame)
        self.frame_email_buttons.pack(pady=5)
        
        self.button_email_text = tk.Button(self.frame_email_buttons, text="Email Encrypted Text", 
                                          command=lambda: self.send_email_text())
        self.button_email_text.grid(row=0, column=0, padx=5)
        
        self.button_email_file = tk.Button(self.frame_email_buttons, text="Email Encrypted File", 
                                          command=lambda: self.send_email_file())
        self.button_email_file.grid(row=0, column=1, padx=5)
        
        self.button_smtp_config = tk.Button(self.frame_email_buttons, text="SMTP Settings", 
                                           command=self.configure_smtp)
        self.button_smtp_config.grid(row=0, column=2, padx=5)
        
        # Key management buttons
        self.frame_key_buttons = tk.Frame(self.main_frame)
        self.frame_key_buttons.pack(pady=5)
        
        self.button_list_keys = tk.Button(self.frame_key_buttons, text="List Available Keys", 
                                         command=self.list_keys)
        self.button_list_keys.grid(row=0, column=0, padx=5)
        
        self.button_key_info = tk.Button(self.frame_key_buttons, text="Key Info", 
                                        command=self.show_key_info)
        self.button_key_info.grid(row=0, column=1, padx=5)

    # ----------------------- Chat Interface -----------------------
    def setup_chat_interface(self):
        # Chat history
        self.chat_history = scrolledtext.ScrolledText(self.chat_frame, width=70, height=20, state='disabled')
        self.chat_history.pack(pady=5)

        # Connection frame
        self.conn_frame = tk.Frame(self.chat_frame)
        self.conn_frame.pack(pady=5)

        # IP address entry
        self.ip_label = tk.Label(self.conn_frame, text="Peer IP:")
        self.ip_label.grid(row=0, column=0, padx=5)
        self.ip_entry = tk.Entry(self.conn_frame, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5)
        self.ip_entry.insert(0, "192.168.1.")  # Example subnet, adjust as needed

        # Buttons for chat connectivity
        self.start_server_btn = tk.Button(self.conn_frame, text="Start Server", command=self.start_server)
        self.start_server_btn.grid(row=0, column=2, padx=5)
        self.connect_btn = tk.Button(self.conn_frame, text="Connect", command=self.connect_to_peer)
        self.connect_btn.grid(row=0, column=3, padx=5)
        self.disconnect_btn = tk.Button(self.conn_frame, text="Disconnect", command=self.disconnect, state='disabled')
        self.disconnect_btn.grid(row=0, column=4, padx=5)

        # Message entry and send button
        self.message_entry = tk.Entry(self.chat_frame, width=50)
        self.message_entry.pack(pady=5)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_btn = tk.Button(self.chat_frame, text="Send", command=self.send_message, state='disabled')
        self.send_btn.pack(pady=5)

        # Status label
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = tk.Label(self.chat_frame, textvariable=self.status_var, fg="red")
        self.status_label.pack(pady=5)

    # ----------------------- Chat Functions -----------------------
    def start_server(self):
        if self.chat_active:
            messagebox.showerror("Error", "Chat is already active.")
            return
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('', 12345))  # Port 12345
            self.server_socket.listen(1)
            self.chat_active = True
            self.update_status("Waiting for connection...", "orange")
            self.toggle_buttons()
            threading.Thread(target=self.accept_connection, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")
            self.server_socket.close()
            self.server_socket = None
            self.chat_active = False

    def accept_connection(self):
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.update_status(f"Connected to {addr[0]}", "green")
            self.start_listening()
        except:
            self.disconnect()

    def connect_to_peer(self):
        if self.chat_active:
            messagebox.showerror("Error", "Chat is already active.")
            return
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Enter peer IP address.")
            return
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, 12345))
            self.chat_active = True
            self.update_status(f"Connected to {ip}", "green")
            self.toggle_buttons()
            self.start_listening()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            self.client_socket = None
            self.chat_active = False

    def start_listening(self):
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

    def listen_for_messages(self):
        while self.chat_active:
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if message:
                    decrypted = self.decrypt_message(message)
                    self.display_message(f"Friend: {decrypted}")
                else:
                    self.disconnect()
            except:
                self.disconnect()
                break

    def send_message(self):
        if not self.chat_active or not self.client_socket:
            messagebox.showerror("Error", "Not connected to a peer.")
            return
        message = self.message_entry.get().strip()
        if not message:
            return
        recipient = self.entry_recipient.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Enter recipient email in the Encrypt/Decrypt tab.")
            return
        encrypted = self.encrypt_message(message, recipient)
        if encrypted:
            try:
                self.client_socket.send(encrypted.encode('utf-8'))
                self.display_message(f"You: {message}")
                self.message_entry.delete(0, tk.END)
            except:
                self.disconnect()

    def encrypt_message(self, message, recipient):
        key_id = self.ensure_recipient_key(recipient)
        if not key_id:
            return ""
        encrypted_data = gpg.encrypt(message, recipients=[recipient], always_trust=True)
        if encrypted_data.ok:
            return str(encrypted_data)
        else:
            messagebox.showerror("Error", f"Encryption failed: {encrypted_data.status}")
            return ""

    def decrypt_message(self, encrypted_message):
        decrypted_data = gpg.decrypt(encrypted_message)
        if decrypted_data.ok:
            return str(decrypted_data)
        else:
            messagebox.showerror("Error", f"Decryption failed: {decrypted_data.status}")
            return "[Decryption Failed]"

    def display_message(self, message):
        self.chat_history.config(state='normal')
        self.chat_history.insert(tk.END, message + "\n")
        self.chat_history.config(state='disabled')
        self.chat_history.see(tk.END)

    def disconnect(self):
        self.chat_active = False
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        self.update_status("Disconnected", "red")
        self.toggle_buttons()

    def update_status(self, text, color):
        self.status_var.set(text)
        self.status_label.config(fg=color)

    def toggle_buttons(self):
        state = 'normal' if self.chat_active else 'disabled'
        self.send_btn.config(state=state)
        self.disconnect_btn.config(state=state)
        self.start_server_btn.config(state='disabled' if self.chat_active else 'normal')
        self.connect_btn.config(state='disabled' if self.chat_active else 'normal')

    # ----------------------- Key Management and Encryption Functions -----------------------
    def list_keys(self):
        """Display a list of available GPG keys."""
        public_keys = gpg.list_keys()
        private_keys = gpg.list_keys(True)  # True for private keys
        
        keys_window = Toplevel(self.master)
        keys_window.title("Available GPG Keys")
        keys_window.geometry("800x500")
        keys_window.transient(self.master)
        
        notebook = tk.ttk.Notebook(keys_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab for public keys
        public_frame = tk.Frame(notebook)
        notebook.add(public_frame, text='Public Keys')
        
        public_text = scrolledtext.ScrolledText(public_frame, width=90, height=20)
        public_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Tab for private keys
        private_frame = tk.Frame(notebook)
        notebook.add(private_frame, text='Private Keys')
        
        private_text = scrolledtext.ScrolledText(private_frame, width=90, height=20)
        private_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Inform users about the keyring location
        public_text.insert(tk.END, "Using system's default GPG keyring (e.g., ~/.gnupg).\n\n")
        private_text.insert(tk.END, "Using system's default GPG keyring (e.g., ~/.gnupg).\n\n")
        
        # Format and display public keys
        if public_keys:
            public_text.insert(tk.END, f"Found {len(public_keys)} public keys:\n\n")
            for key in public_keys:
                public_text.insert(tk.END, f"Key ID: {key['keyid']}\n")
                public_text.insert(tk.END, f"Fingerprint: {key['fingerprint']}\n")
                public_text.insert(tk.END, f"Creation date: {key['date']}\n")
                public_text.insert(tk.END, "User IDs:\n")
                for uid in key['uids']:
                    public_text.insert(tk.END, f"  - {uid}\n")
                public_text.insert(tk.END, "\n" + "-"*70 + "\n\n")
        else:
            public_text.insert(tk.END, "No public keys found in the keyring.\n")
            public_text.insert(tk.END, "\nTo import a key, use 'gpg --import' in your terminal or encrypt a message with a recipient's email.")
        
        # Format and display private keys
        if private_keys:
            private_text.insert(tk.END, f"Found {len(private_keys)} private keys:\n\n")
            for key in private_keys:
                private_text.insert(tk.END, f"Key ID: {key['keyid']}\n")
                private_text.insert(tk.END, f"Fingerprint: {key['fingerprint']}\n")
                private_text.insert(tk.END, f"Creation date: {key['date']}\n")
                private_text.insert(tk.END, "User IDs:\n")
                for uid in key['uids']:
                    private_text.insert(tk.END, f"  - {uid}\n")
                private_text.insert(tk.END, "\n" + "-"*70 + "\n\n")
        else:
            private_text.insert(tk.END, "No private keys found in the keyring.\n")
            private_text.insert(tk.END, "\nYou need a private key to decrypt messages. Generate one with 'gpg --gen-key' in your terminal.")
        
        public_text.config(state=tk.DISABLED)
        private_text.config(state=tk.DISABLED)
        
        Button(keys_window, text="Close", command=keys_window.destroy).pack(pady=10)
        
    def show_key_info(self):
        """Show detailed info about a specific key."""
        key_id = simpledialog.askstring("Key Info", "Enter Key ID, Fingerprint, or Email address:")
        if not key_id:
            return
            
        # Try to find the key
        key_found = False
        key_info = None
        
        public_keys = gpg.list_keys()
        private_keys = gpg.list_keys(True)
        
        for key in public_keys + private_keys:
            if (key_id.lower() in key['keyid'].lower() or 
                (key['fingerprint'] and key_id.lower() in key['fingerprint'].lower())):
                key_info = key
                key_found = True
                break
                
            for uid in key['uids']:
                if key_id.lower() in uid.lower():
                    key_info = key
                    key_found = True
                    break
            
            if key_found:
                break
                
        if not key_found:
            messagebox.showinfo("No Key Found", f"No key found matching '{key_id}'")
            return
            
        info_window = Toplevel(self.master)
        info_window.title(f"Key Info: {key_id}")
        info_window.geometry("600x400")
        info_window.transient(self.master)
        
        info_text = scrolledtext.ScrolledText(info_window, width=70, height=20)
        info_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        info_text.insert(tk.END, f"Key ID: {key_info['keyid']}\n")
        info_text.insert(tk.END, f"Fingerprint: {key_info['fingerprint']}\n")
        info_text.insert(tk.END, f"Creation date: {key_info['date']}\n")
        info_text.insert(tk.END, f"Key type: {'Private' if key_info in private_keys else 'Public'}\n\n")
        
        info_text.insert(tk.END, "User IDs:\n")
        for uid in key_info['uids']:
            info_text.insert(tk.END, f"  - {uid}\n")
            
        if key_info in private_keys:
            info_text.insert(tk.END, "\nThis key can be used to decrypt messages.\n")
        else:
            info_text.insert(tk.END, "\nThis key can only be used to encrypt messages. You need the corresponding private key to decrypt.\n")
            
        info_text.config(state=tk.DISABLED)
        
        Button(info_window, text="Close", command=info_window.destroy).pack(pady=10)

    def get_public_key_emails(self):
        """Retrieve a sorted list of unique email addresses from public keys."""
        public_keys = gpg.list_keys()
        emails = set()
        for key in public_keys:
            for uid in key['uids']:
                if '<' in uid and '>' in uid:
                    email = uid.split('<')[1].split('>')[0]
                    emails.add(email)
        return sorted(list(emails))

    def find_key_for_email(self, email):
        keys = gpg.list_keys()
        logger.info(f"Looking for key matching email: {email}")
        for key in keys:
            for uid in key['uids']:
                if email.lower() == uid.lower() or f"<{email.lower()}>" in uid.lower():
                    logger.info(f"Found matching key: {key['keyid']} for {email}")
                    return key['keyid']
        logger.warning(f"No key found for email: {email}")
        return None

    def fetch_public_key(self, email):
        encoded_email = urllib.parse.quote(email)
        url = f"https://keys.openpgp.org/vks/v1/by-email/{encoded_email}"
        try:
            response = requests.get(url)
            if response.status_code == 200 and response.text.strip():
                import_result = gpg.import_keys(response.text)
                if import_result.count > 0:
                    keyid = self.find_key_for_email(email)
                    if keyid:
                        messagebox.showinfo("Success", f"Imported key for {email}")
                        return keyid
                return None
            else:
                messagebox.showinfo("Key Not Found", f"No key found for {email}")
                return None
        except requests.RequestException as e:
            messagebox.showerror("Network Error", f"Failed to fetch key: {e}")
            return None

    def prompt_for_public_key(self):
        public_key = simpledialog.askstring("Public Key Required", 
                                          "Could not find public key.\nPaste the recipient's public key:")
        if not public_key:
            return None
        import_result = gpg.import_keys(public_key)
        if import_result.count > 0:
            return import_result.fingerprints[0] if import_result.fingerprints else True
        else:
            messagebox.showerror("Error", "Invalid public key.")
            return None

    def ensure_recipient_key(self, recipient):
        key_id = self.find_key_for_email(recipient)
        if key_id:
            return key_id
        key_id = self.fetch_public_key(recipient)
        if key_id:
            return key_id
        return self.prompt_for_public_key()

    def encrypt_text(self):
        recipient = self.entry_recipient.get().strip()
        plain_text = self.text_area.get(1.0, tk.END).strip()
        if not recipient or not plain_text:
            messagebox.showerror("Error", "Recipient email and text required.")
            return
        key_id = self.ensure_recipient_key(recipient)
        if not key_id:
            messagebox.showerror("Error", "No valid public key available.")
            return
        encrypted_data = gpg.encrypt(plain_text, recipients=[recipient], always_trust=True)
        if encrypted_data.ok:
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, str(encrypted_data))
            messagebox.showinfo("Success", "Text encrypted successfully.")
        else:
            messagebox.showerror("Encryption Failed", f"Failed to encrypt: {encrypted_data.status}")

    def decrypt_text(self):
        encrypted_text = self.text_area.get(1.0, tk.END).strip()
        if not encrypted_text:
            messagebox.showerror("Error", "Encrypted text required.")
            return
        private_keys = gpg.list_keys(True)
        if not private_keys:
            messagebox.showerror("No Private Keys", "No private keys found.")
            return
        decrypted_data = gpg.decrypt(encrypted_text)
        if decrypted_data.ok:
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, str(decrypted_data))
            messagebox.showinfo("Success", "Text decrypted successfully.")
        else:
            messagebox.showerror("Decryption Failed", f"Failed to decrypt: {decrypted_data.status}")

    def generate_key_pair(self):
        key_gen_window = Toplevel(self.master)
        key_gen_window.title("Generate New Key Pair")
        key_gen_window.geometry("500x350")
        key_gen_window.transient(self.master)
        key_gen_window.grab_set()
        
        Label(key_gen_window, text="Full Name:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        name_entry = Entry(key_gen_window, width=40)
        name_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        Label(key_gen_window, text="Email Address:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        email_entry = Entry(key_gen_window, width=40)
        email_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        
        Label(key_gen_window, text="Comment (optional):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        comment_entry = Entry(key_gen_window, width=40)
        comment_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        
        Label(key_gen_window, text="Key Type:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        key_type_var = tk.StringVar(value="RSA")
        key_type_options = tk.ttk.Combobox(key_gen_window, textvariable=key_type_var, 
                                         values=["RSA", "DSA and ElGamal", "ECC"], state="readonly", width=38)
        key_type_options.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        
        Label(key_gen_window, text="Key Length:").grid(row=4, column=0, sticky="w", padx=10, pady=5)
        key_length_var = tk.StringVar(value="2048")
        key_length_options = tk.ttk.Combobox(key_gen_window, textvariable=key_length_var, 
                                           values=["1024", "2048", "3072", "4096"], state="readonly", width=38)
        key_length_options.grid(row=4, column=1, padx=10, pady=5, sticky="w")
        
        Label(key_gen_window, text="Passphrase:").grid(row=5, column=0, sticky="w", padx=10, pady=5)
        passphrase_entry = Entry(key_gen_window, width=40, show="*")
        passphrase_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")
        
        Label(key_gen_window, text="Confirm Passphrase:").grid(row=6, column=0, sticky="w", padx=10, pady=5)
        confirm_passphrase_entry = Entry(key_gen_window, width=40, show="*")
        confirm_passphrase_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")
        
        status_var = tk.StringVar()
        status_label = Label(key_gen_window, textvariable=status_var, fg="blue")
        status_label.grid(row=7, column=0, columnspan=2, padx=10, pady=5)
        
        def generate_key():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            comment = comment_entry.get().strip()
            key_type = key_type_var.get()
            key_length = key_length_var.get()
            passphrase = passphrase_entry.get()
            confirm_passphrase = confirm_passphrase_entry.get()
            
            if not name:
                messagebox.showerror("Error", "Full name is required")
                return
                
            if not email:
                messagebox.showerror("Error", "Email address is required")
                return
                
            if passphrase != confirm_passphrase:
                messagebox.showerror("Error", "Passphrases do not match")
                return
                
            key_type_map = {
                "RSA": "RSA",
                "DSA and ElGamal": "DSA",
                "ECC": "ECC"
            }
            
            key_params = {
                'name_real': name,
                'name_email': email,
                'expire_date': '0',
                'key_type': key_type_map[key_type],
                'key_length': int(key_length),
                'key_usage': 'encrypt,sign,auth',
                'passphrase': passphrase
            }
            
            if comment:
                key_params['name_comment'] = comment
                
            def key_gen_thread():
                status_var.set("Generating key pair... This may take a while.")
                generate_button.config(state=tk.DISABLED)
                cancel_button.config(state=tk.DISABLED)
                
                try:
                    key = gpg.gen_key(gpg.gen_key_input(**key_params))
                    if key:
                        logger.info(f"Generated new key with fingerprint: {key.fingerprint}")
                        status_var.set("Key pair generated successfully!")
                        self.entry_recipient.delete(0, tk.END)
                        self.entry_recipient.insert(0, email)
                        key_gen_window.after(2000, key_gen_window.destroy)
                    else:
                        status_var.set("Failed to generate key pair.")
                        generate_button.config(state=tk.NORMAL)
                        cancel_button.config(state=tk.NORMAL)
                except Exception as e:
                    logger.error(f"Key generation error: {str(e)}")
                    status_var.set(f"Error: {str(e)}")
                    generate_button.config(state=tk.NORMAL)
                    cancel_button.config(state=tk.NORMAL)
            
            threading.Thread(target=key_gen_thread, daemon=True).start()
        
        button_frame = tk.Frame(key_gen_window)
        button_frame.grid(row=8, column=0, columnspan=2, pady=15)
        
        generate_button = Button(button_frame, text="Generate Key Pair", command=generate_key)
        generate_button.pack(side=tk.LEFT, padx=10)
        
        cancel_button = Button(button_frame, text="Cancel", command=key_gen_window.destroy)
        cancel_button.pack(side=tk.LEFT, padx=10)

    def encrypt_file(self):
        recipient = self.entry_recipient.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Recipient email required.")
            return
        key_id = self.ensure_recipient_key(recipient)
        if not key_id:
            messagebox.showerror("Error", "No valid public key available for encryption.")
            return
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
        if os.path.getsize(file_path) > 100 * 1024 * 1024:
            messagebox.showerror("Error", "File size exceeds 100 MB limit.")
            return
        output_path = file_path + ".gpg"
        logger.info(f"Encrypting file: {file_path} for recipient: {recipient}")
        with open(file_path, 'rb') as f:
            status = gpg.encrypt_file(f, recipients=[recipient], output=output_path, always_trust=True)
        if status.ok:
            logger.info(f"File encrypted successfully: {output_path}")
            messagebox.showinfo("Success", f"File encrypted successfully:\n{output_path}")
        else:
            logger.error(f"File encryption failed: {status.status}")
            messagebox.showerror("Encryption Failed", f"Failed to encrypt file: {status.status}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt", 
                                              filetypes=[("GPG Files", "*.gpg"), ("All Files", "*.*")])
        if not file_path:
            return
        if os.path.getsize(file_path) > 100 * 1024 * 1024:
            messagebox.showerror("Error", "File size exceeds 100 MB limit.")
            return
        if file_path.lower().endswith('.gpg'):
            output_path = file_path[:-4]
        else:
            output_path = file_path + ".decrypted"
        output_path = filedialog.asksaveasfilename(title="Save Decrypted File As", 
                                                  initialfile=os.path.basename(output_path))
        if not output_path:
            return
        logger.info(f"Decrypting file: {file_path} to: {output_path}")
        with open(file_path, 'rb') as f:
            status = gpg.decrypt_file(f, output=output_path)
        if status.ok:
            logger.info("File decrypted successfully")
            messagebox.showinfo("Success", f"File decrypted successfully:\n{output_path}")
        else:
            logger.error(f"File decryption failed: {status.status}")
            messagebox.showerror("Decryption Failed", f"Failed to decrypt file: {status.status}")

    def configure_smtp(self):
        config_window = Toplevel(self.master)
        config_window.title("SMTP Configuration")
        config_window.geometry("400x250")
        config_window.transient(self.master)
        config_window.grab_set()
        
        Label(config_window, text="SMTP Server:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        server_entry = Entry(config_window, width=30)
        server_entry.grid(row=0, column=1, padx=10, pady=5)
        server_entry.insert(0, self.smtp_config.get('server', ''))
        
        Label(config_window, text="SMTP Port:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        port_entry = Entry(config_window, width=30)
        port_entry.grid(row=1, column=1, padx=10, pady=5)
        port_entry.insert(0, str(self.smtp_config.get('port', 587)))
        
        Label(config_window, text="Username:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        username_entry = Entry(config_window, width=30)
        username_entry.grid(row=2, column=1, padx=10, pady=5)
        username_entry.insert(0, self.smtp_config.get('username', ''))
        
        Label(config_window, text="Password:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        password_entry = Entry(config_window, width=30, show="*")
        password_entry.grid(row=3, column=1, padx=10, pady=5)
        password_entry.insert(0, self.smtp_config.get('password', ''))
        
        use_tls_var = tk.BooleanVar(value=self.smtp_config.get('use_tls', True))
        use_tls_check = tk.Checkbutton(config_window, text="Use TLS", variable=use_tls_var)
        use_tls_check.grid(row=4, column=0, columnspan=2, pady=5)
        
        def save_config():
            try:
                self.smtp_config = {
                    'server': server_entry.get().strip(),
                    'port': int(port_entry.get().strip()),
                    'username': username_entry.get().strip(),
                    'password': password_entry.get(),
                    'use_tls': use_tls_var.get()
                }
                config = configparser.ConfigParser()
                config['SMTP'] = {
                    'server': self.smtp_config['server'],
                    'port': str(self.smtp_config['port']),
                    'username': self.smtp_config['username'],
                    'password': self.smtp_config['password'],
                    'use_tls': str(self.smtp_config['use_tls'])
                }
                with open('mail_config.ini', 'w') as f:
                    config.write(f)
                messagebox.showinfo("Success", "SMTP settings saved successfully.")
                config_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
        
        def test_connection():
            try:
                server = server_entry.get().strip()
                port = int(port_entry.get().strip())
                username = username_entry.get().strip()
                password = password_entry.get()
                use_tls = use_tls_var.get()
                if not server or not port:
                    messagebox.showerror("Error", "Server and port are required.")
                    return
                smtp = smtplib.SMTP(server, port)
                smtp.ehlo()
                if use_tls:
                    smtp.starttls()
                    smtp.ehlo()
                if username and password:
                    smtp.login(username, password)
                smtp.quit()
                messagebox.showinfo("Success", "SMTP connection test successful!")
            except Exception as e:
                messagebox.showerror("Error", f"SMTP connection failed: {str(e)}")
        
        button_frame = tk.Frame(config_window)
        button_frame.grid(row=5, column=0, columnspan=2, pady=15)
        
        Button(button_frame, text="Test Connection", command=test_connection).pack(side=tk.LEFT, padx=10)
        Button(button_frame, text="Save", command=save_config).pack(side=tk.LEFT, padx=10)
        Button(button_frame, text="Cancel", command=config_window.destroy).pack(side=tk.LEFT, padx=10)
    
    def compose_email(self, recipient, attachment_path=None, message_text=None):
        if not self.smtp_config.get('server'):
            response = messagebox.askyesno("SMTP Not Configured", 
                                          "SMTP server is not configured. Would you like to configure it now?")
            if response:
                self.configure_smtp()
            return False
            
        email_window = Toplevel(self.master)
        email_window.title("Compose Email")
        email_window.geometry("600x550")
        email_window.transient(self.master)
        email_window.grab_set()
        
        Label(email_window, text="To:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        to_entry = Entry(email_window, width=50)
        to_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        to_entry.insert(0, recipient)
        
        Label(email_window, text="From:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        from_entry = Entry(email_window, width=50)
        from_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        from_entry.insert(0, self.smtp_config.get('username', ''))
        
        Label(email_window, text="Subject:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        subject_entry = Entry(email_window, width=50)
        subject_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        subject_entry.insert(0, "Encrypted Message")
        
        Label(email_window, text="Message:").grid(row=3, column=0, sticky="nw", padx=10, pady=5)
        message_text_widget = Text(email_window, width=50, height=15)
        message_text_widget.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        
        default_message = "I've sent you an encrypted message."
        if attachment_path:
            default_message += f"\n\nPlease find the encrypted file attached."
        elif message_text:
            default_message += "\n\nThe encrypted content is included in this email."
            
        message_text_widget.insert(tk.END, default_message)
        
        if attachment_path:
            attachment_label = Label(email_window, text=f"Attachment: {os.path.basename(attachment_path)}")
            attachment_label.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="w")
        
        status_var = tk.StringVar()
        status_label = Label(email_window, textvariable=status_var, fg="blue")
        status_label.grid(row=5, column=0, columnspan=2, padx=10, pady=5)
        
        def send_email_thread():
            status_var.set("Sending email...")
            send_button.config(state=tk.DISABLED)
            try:
                msg = MIMEMultipart()
                msg['From'] = from_entry.get().strip()
                msg['To'] = to_entry.get().strip()
                msg['Subject'] = subject_entry.get().strip()
                msg.attach(MIMEText(message_text_widget.get(1.0, tk.END), 'plain'))
                if message_text:
                    msg.attach(MIMEText("\n\n----- ENCRYPTED MESSAGE BEGINS -----\n\n", 'plain'))
                    msg.attach(MIMEText(message_text, 'plain'))
                    msg.attach(MIMEText("\n\n----- ENCRYPTED MESSAGE ENDS -----\n\n", 'plain'))
                if attachment_path:
                    with open(attachment_path, 'rb') as f:
                        attachment = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
                    attachment['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                    msg.attach(attachment)
                with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as smtp:
                    smtp.ehlo()
                    if self.smtp_config['use_tls']:
                        smtp.starttls()
                        smtp.ehlo()
                    if self.smtp_config['username'] and self.smtp_config['password']:
                        smtp.login(self.smtp_config['username'], self.smtp_config['password'])
                    smtp.send_message(msg)
                status_var.set("Email sent successfully!")
                logger.info(f"Email sent to {to_entry.get().strip()}")
                email_window.after(2000, email_window.destroy)
            except Exception as e:
                logger.error(f"Failed to send email: {str(e)}")
                status_var.set(f"Error: {str(e)}")
                send_button.config(state=tk.NORMAL)
        
        def send_email_action():
            threading.Thread(target=send_email_thread, daemon=True).start()
        
        button_frame = tk.Frame(email_window)
        button_frame.grid(row=6, column=0, columnspan=2, pady=15)
        
        send_button = Button(button_frame, text="Send Email", command=send_email_action)
        send_button.pack(side=tk.LEFT, padx=10)
        
        Button(button_frame, text="Cancel", command=email_window.destroy).pack(side=tk.LEFT, padx=10)
        
        return True
    
    def send_email_text(self):
        recipient = self.entry_recipient.get().strip()
        encrypted_text = self.text_area.get(1.0, tk.END).strip()
        if not recipient:
            messagebox.showerror("Error", "Recipient email required.")
            return
        if not encrypted_text:
            messagebox.showerror("Error", "No encrypted text to send.")
            return
        if not encrypted_text.startswith('-----BEGIN PGP MESSAGE-----'):
            response = messagebox.askyesno("Warning", "The text doesn't appear to be encrypted. Encrypt it now?")
            if response:
                self.encrypt_text()
                encrypted_text = self.text_area.get(1.0, tk.END).strip()
            else:
                return
        self.compose_email(recipient, message_text=encrypted_text)
    
    def send_email_file(self):
        recipient = self.entry_recipient.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Recipient email required.")
            return
        file_path = filedialog.askopenfilename(title="Select Encrypted File to Send", 
                                              filetypes=[("GPG Files", "*.gpg"), ("All Files", "*.*")])
        if not file_path:
            return
        if not file_path.lower().endswith('.gpg'):
            response = messagebox.askyesno("Warning", "The file doesn't appear to be encrypted. Encrypt it now?")
            if response:
                key_id = self.ensure_recipient_key(recipient)
                if not key_id:
                    messagebox.showerror("Error", "No valid public key available for encryption.")
                    return
                output_path = file_path + ".gpg"
                with open(file_path, 'rb') as f:
                    status = gpg.encrypt_file(f, recipients=[recipient], output=output_path, always_trust=True)
                if status.ok:
                    file_path = output_path
                else:
                    messagebox.showerror("Encryption Failed", f"Failed to encrypt file: {status.status}")
                    return
            else:
                return
        self.compose_email(recipient, attachment_path=file_path)

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    app = GPGApp(root)
    root.mainloop()
