function showSection(sectionId) {
    document.getElementById('generate').style.display = 'none';
    document.getElementById('encrypt').style.display = 'none';
    document.getElementById('decrypt').style.display = 'none';
    document.getElementById(sectionId).style.display = 'block';
}

async function generateKeys() {
    try {
        const { privateKey, publicKey } = await openpgp.generateKey({
            type: 'rsa',
            rsaBits: 2048,
            userIDs: [{ name: 'User', email: 'user@example.com' }],
            passphrase: ''
        });

        document.getElementById('publicKey').value = publicKey;
        document.getElementById('privateKey').value = privateKey;
    } catch (error) {
        console.error("Key generation failed:", error);
    }
}

async function encryptMessage() {
    const message = document.getElementById('messageToEncrypt').value;
    const publicKeyArmored = document.getElementById('encryptPublicKey').value;

    if (!message || !publicKeyArmored) {
        alert("Please enter both the message and the public key.");
        return;
    }

    try {
        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: message }),
            encryptionKeys: publicKey
        });

        document.getElementById('encryptedMessage').value = encrypted;
    } catch (error) {
        console.error("Encryption failed:", error);
        alert("Encryption failed. Please check the public key format.");
    }
}

async function decryptMessage() {
    const encryptedMessage = document.getElementById('messageToDecrypt').value;
    const privateKeyArmored = document.getElementById('decryptPrivateKey').value;

    if (!encryptedMessage || !privateKeyArmored) {
        alert("Please enter both the encrypted message and the private key.");
        return;
    }

    try {
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

        const message = await openpgp.readMessage({
            armoredMessage: encryptedMessage
        });

        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: privateKey
        });

        document.getElementById('decryptedMessage').value = decrypted;
    } catch (error) {
        console.error("Decryption failed:", error);
        alert("Decryption failed. Please check the private key and the message format.");
    }
}

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).value;
    if (text) {
        navigator.clipboard.writeText(text).then(() => {
            alert("Text copied to clipboard.");
        }).catch(err => {
            console.error("Could not copy text:", err);
        });
    } else {
        alert("Nothing to copy!");
    }
}
