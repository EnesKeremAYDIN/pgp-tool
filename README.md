# PGP Key Generator & Encrypt/Decrypt Tool

Web-based tool to generate PGP keys, encrypt messages, and decrypt messages securely using the OpenPGP.js library. This application allows users to manage PGP (Pretty Good Privacy) encryption and decryption operations directly from the browser.

## Features

- **Generate PGP Keys**: Create public and private PGP key pairs.
- **Encrypt Messages**: Encrypt plaintext messages using a public key.
- **Decrypt Messages**: Decrypt ciphertext messages using a private key.
- **Copy to Clipboard**: Convenient buttons to copy generated keys and messages to the clipboard.
- **User-friendly Interface**: Designed with an accessible layout using HTML, CSS, and JavaScript.

## Installation and Usage

1. **Clone or Download** the repository:
   ```bash
   git clone https://github.com/EnesKeremAYDIN/pgp-tool.git
   cd pgp-tool
   ```

2. **Run the Application**:
   - Open `index.html` in a web browser to access the PGP tool.

## Files

- **`index.html`**: Main HTML structure of the tool, defining sections for key generation, encryption, and decryption.
- **`script.js`**: JavaScript code implementing PGP key generation, encryption, and decryption using OpenPGP.js.
- **`style.css`**: CSS file for styling the tool interface, providing a dark-themed, responsive layout.

## Requirements

- A web browser with JavaScript enabled.
- OpenPGP.js library (loaded via CDN in the HTML file).

## Disclaimer

This tool is intended for educational and personal use. Ensure proper security practices for storing and handling PGP keys.

---

### Usage Instructions

1. **Generate Keys**:
   - Navigate to the "Generate Keys" section and click "Generate Keys" to create a PGP key pair.
   - Use the "Copy" button to copy generated keys as needed.

2. **Encrypt a Message**:
   - Go to the "Encrypt Message" section.
   - Input the plaintext message and paste the recipient's public key.
   - Click "Encrypt" to generate the encrypted message, which you can then copy.

3. **Decrypt a Message**:
   - Navigate to the "Decrypt Message" section.
   - Paste the encrypted message and your private key.
   - Click "Decrypt" to reveal the original message.

