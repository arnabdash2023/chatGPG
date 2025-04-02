# chatGPG

A secure, encrypted messaging application that combines GPG encryption with peer-to-peer chat and email functionality.

![image](https://github.com/user-attachments/assets/e7b10841-1308-45dc-8770-e12636ac9000)
![image](https://github.com/user-attachments/assets/4f4ab4dd-fe3e-451b-a7f8-6716d5fd810f)
![image](https://github.com/user-attachments/assets/68a72d6c-7ea4-469c-b634-12a0247a9779)
![image](https://github.com/user-attachments/assets/927c0571-cb57-4cdf-830a-2ba3ff416b58)

## Features

### Encryption and Decryption
- Text and file encryption/decryption using GPG
- Public and private key management
- Integration with public key servers (keys.openpgp.org)
- Support for various key types (RSA, DSA/ElGamal, ECC)

### P2P Encrypted Chat
- Direct peer-to-peer encrypted messaging
- Server/client architecture for establishing connections
- Real-time communication with end-to-end encryption

### Secure Email
- Send encrypted messages via email
- Attach encrypted files to emails
- Configurable SMTP settings for email integration

## Prerequisites

- Python 3.6 or newer
- GPG (GnuPG) installed on your system
- Internet connection for key server and email features
- Basic understanding of GPG encryption concepts

## Installation

1. Clone the repository or download the source code

   ```bash
   git clone https://github.com/yourusername/gpgchat.git
   cd gpgchat
   ```

2. Install the required Python packages

   ```bash
   pip install -r requirements.txt
   ```

   Required packages include:
   - tkinter
   - python-gnupg
   - requests
   - configparser

3. Ensure GPG is installed on your system
   - For Linux: `sudo apt-get install gnupg` (Debian/Ubuntu)
   - For macOS: `brew install gnupg` (using Homebrew)
   - For Windows: Download and install GPG4Win from https://gpg4win.org/

## Usage

### Starting the Application

Run the application using Python:

```bash
python app.py
```

### Encryption/Decryption Tab

1. **Encrypting Text**
   - Enter the recipient's email in the "Recipient Email" field
   - Type or paste your message in the text area
   - Click "Encrypt Text"
   - The encrypted message will appear in the text area

2. **Decrypting Text**
   - Paste the encrypted message in the text area
   - Click "Decrypt Text"
   - The decrypted message will appear in the text area

3. **Encrypting Files**
   - Enter the recipient's email
   - Click "Encrypt File" and select the file to encrypt
   - The encrypted file will be saved with a .gpg extension

4. **Decrypting Files**
   - Click "Decrypt File" and select the encrypted file
   - Choose where to save the decrypted file

5. **Managing Keys**
   - Click "List Available Keys" to see all keys in your keyring
   - Click "Key Info" to view detailed information about a specific key

6. **Email Features**
   - Configure SMTP settings by clicking "SMTP Settings"
   - Send encrypted text or files directly via email

### P2P Chat Tab

1. **Starting a Chat Server**
   - Find the IP of your system using the following command and paste in the Peer IP box

   ```bash
   ip addr show | grep -oP '192\.168\.\d+\.\d+' | head -n 1
   ```

   - Click "Start Server" to listen for incoming connections
   - Your friend can then connect to your IP address

2. **Connecting to a Peer**
   - Enter the peer's IP address
   - Click "Connect" to establish a connection
   - Once connected, you can send encrypted messages

3. **Sending Messages**
   - Type your message in the entry field
   - Press Enter or click "Send"
   - Messages are automatically encrypted using GPG

## Configuration

### SMTP Settings

Email functionality requires SMTP configuration:

1. Click "SMTP Settings" in the main interface
2. Enter your SMTP server details:
   - Server address
   - Port
   - Username
   - Password
   - TLS setting
3. Test the connection before saving

#### For Gmail users

For Gmail users with 2FA enabled on their system, you have to set the folllowing details in `mail_config.ini` or when prompted in GUI
- server: `smtp.gmail.com`
- port: `587`
- username: `<gmail address>`
- password: [Follow this link to generate 16-digit App Password](https://support.google.com/mail/answer/185833?hl=en)
- use_tls: `True`

Settings are stored in `mail_config.ini`.

### GPG Keyring

The application uses your system's default GPG keyring (typically ~/.gnupg). You can manage keys through the application or using the GPG command line tools.

## Security Considerations

- **Passphrase Protection**: Always use strong passphrases for your private keys
- **Key Verification**: Verify key fingerprints through secure channels
- **System Security**: Keep your operating system and GPG installation updated
- **Network Security**: Be aware that P2P connections may be affected by firewalls or NAT

## Troubleshooting

### Common Issues

1. **GPG Not Found**
   - Ensure GPG is installed and accessible in your system's PATH
   - Restart the application after installing GPG

2. **Key Import Failures**
   - Verify the key format is correct
   - Check internet connectivity for key server operations

3. **Chat Connection Problems**
   - Ensure firewall settings allow connections on port 12345
   - Verify the correct IP address is being used
   - Check if the server is running before attempting to connect

4. **Email Sending Failures**
   - Verify SMTP settings are correct
   - Check if your email provider allows SMTP access
   - Some providers require app-specific passwords for SMTP access

## License

GNU General Public License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

*Note: This application is designed for educational purposes and personal use. For production environments with sensitive data, consider professional security auditing.*
