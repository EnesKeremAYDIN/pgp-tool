const sectionIds = ['generate', 'encrypt', 'decrypt'];
const statusIds = ['generateStatus', 'encryptStatus', 'decryptStatus'];
const menuButtons = Array.from(document.querySelectorAll('.menu button'));

function showSection(sectionId) {
    sectionIds.forEach((id) => {
        const section = document.getElementById(id);
        section.style.display = id === sectionId ? 'block' : 'none';
    });

    menuButtons.forEach((button) => {
        button.classList.toggle('active', button.dataset.section === sectionId);
    });
}

async function generateKeys() {
    clearStatuses();
    clearKeyOutputs();

    const name = getValue('userName').trim() || 'PGP User';
    const email = getValue('userEmail').trim();
    const passphrase = getValue('generatePassphrase');
    const confirmPassphrase = getValue('confirmPassphrase');

    if (!passphrase) {
        setStatus('generateStatus', 'Private key passphrase is required.', 'error');
        return;
    }

    if (passphrase.length < 12) {
        setStatus('generateStatus', 'Use a passphrase with at least 12 characters.', 'error');
        return;
    }

    if (passphrase !== confirmPassphrase) {
        setStatus('generateStatus', 'Passphrase confirmation does not match.', 'error');
        return;
    }

    if (email && !isValidEmail(email)) {
        setStatus('generateStatus', 'Email format is invalid.', 'error');
        return;
    }

    setStatus('generateStatus', 'Generating key pair...', 'info');

    try {
        ensureOpenPgpLoaded();

        const userIDs = [{ name, ...(email ? { email } : {}) }];
        const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
            type: 'ecc',
            curve: 'curve25519',
            userIDs,
            passphrase
        });

        setValue('publicKey', publicKey);
        setValue('privateKey', privateKey);
        setValue('revocationCertificate', revocationCertificate || '');
        setStatus('generateStatus', 'Key pair generated successfully.', 'success');
    } catch (error) {
        console.error('Key generation failed:', error);
        setStatus('generateStatus', getErrorMessage(error, 'Key generation failed.'), 'error');
    }
}

async function encryptMessage() {
    clearStatuses();
    setValue('encryptedMessage', '');

    const messageText = getValue('messageToEncrypt').trim();
    const publicKeyArmored = getValue('encryptPublicKey').trim();

    if (!messageText) {
        setStatus('encryptStatus', 'Enter or load a plaintext message.', 'error');
        return;
    }

    if (!publicKeyArmored) {
        setStatus('encryptStatus', 'Enter or load a recipient public key.', 'error');
        return;
    }

    setStatus('encryptStatus', 'Encrypting message...', 'info');

    try {
        ensureOpenPgpLoaded();

        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: messageText }),
            encryptionKeys: publicKey,
            format: 'armored'
        });

        setValue('encryptedMessage', encrypted);
        setStatus('encryptStatus', 'Message encrypted successfully.', 'success');
    } catch (error) {
        console.error('Encryption failed:', error);
        setStatus('encryptStatus', getErrorMessage(error, 'Encryption failed. Check the public key and message.'), 'error');
    }
}

async function decryptMessage() {
    clearStatuses();
    setValue('decryptedMessage', '');

    const encryptedMessage = getValue('messageToDecrypt').trim();
    const privateKeyArmored = getValue('decryptPrivateKey').trim();
    const passphrase = getValue('decryptPassphrase');

    if (!encryptedMessage) {
        setStatus('decryptStatus', 'Enter or load an encrypted message.', 'error');
        return;
    }

    if (!privateKeyArmored) {
        setStatus('decryptStatus', 'Enter or load a private key.', 'error');
        return;
    }

    setStatus('decryptStatus', 'Decrypting message...', 'info');

    try {
        ensureOpenPgpLoaded();

        const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });
        const privateKey = await resolvePrivateKey(privateKeyArmored, passphrase);
        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: privateKey,
            format: 'utf8'
        });

        setValue('decryptedMessage', decrypted);
        setStatus('decryptStatus', 'Message decrypted successfully.', 'success');
    } catch (error) {
        console.error('Decryption failed:', error);
        setStatus('decryptStatus', getErrorMessage(error, 'Decryption failed. Check the private key, passphrase, and message.'), 'error');
    }
}

function copyToClipboard(elementId) {
    const text = getValue(elementId);

    if (!text) {
        alert('Nothing to copy.');
        return;
    }

    if (window.isSecureContext && navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Text copied to clipboard.');
        }).catch((error) => {
            console.error('Could not copy text:', error);
            fallbackCopyText(text);
        });
        return;
    }

    fallbackCopyText(text);
}

function downloadTextFile(elementId, filename) {
    const text = getValue(elementId);

    if (!text) {
        alert('Nothing to download.');
        return;
    }

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function loadTextFileIntoField(event, targetFieldId) {
    const [file] = event.target.files;

    if (!file) {
        return;
    }

    const reader = new FileReader();

    reader.onload = ({ target }) => {
        setValue(targetFieldId, typeof target.result === 'string' ? target.result : '');
    };

    reader.onerror = () => {
        console.error('File read failed:', reader.error);
        const targetStatusId = getStatusIdForField(targetFieldId);
        setStatus(targetStatusId, 'The selected file could not be read.', 'error');
    };

    reader.readAsText(file);
    event.target.value = '';
}

function fallbackCopyText(text) {
    const helper = document.createElement('textarea');
    helper.value = text;
    helper.setAttribute('readonly', '');
    helper.style.position = 'fixed';
    helper.style.opacity = '0';
    document.body.appendChild(helper);
    helper.select();
    helper.setSelectionRange(0, helper.value.length);

    try {
        document.execCommand('copy');
        alert('Text copied to clipboard.');
    } catch (error) {
        console.error('Fallback copy failed:', error);
        alert('Clipboard access failed.');
    }

    document.body.removeChild(helper);
}

async function resolvePrivateKey(privateKeyArmored, passphrase) {
    const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

    if (passphrase) {
        return openpgp.decryptKey({
            privateKey,
            passphrase
        });
    }

    if (typeof privateKey.isDecrypted === 'function' && !privateKey.isDecrypted()) {
        throw new Error('This private key is passphrase protected. Enter the passphrase to continue.');
    }

    return privateKey;
}

function ensureOpenPgpLoaded() {
    if (!window.openpgp) {
        throw new Error('OpenPGP.js could not be loaded. Check your internet connection and reload the page.');
    }
}

function getErrorMessage(error, fallback) {
    if (!error) {
        return fallback;
    }

    const message = typeof error.message === 'string' ? error.message.trim() : '';

    if (!message) {
        return fallback;
    }

    if (message.toLowerCase().includes('passphrase')) {
        return message;
    }

    if (message.toLowerCase().includes('misformed armored text')) {
        return 'The provided PGP text is invalid or incomplete.';
    }

    return message;
}

function getStatusIdForField(fieldId) {
    if (fieldId === 'messageToEncrypt' || fieldId === 'encryptPublicKey') {
        return 'encryptStatus';
    }

    if (fieldId === 'messageToDecrypt' || fieldId === 'decryptPrivateKey') {
        return 'decryptStatus';
    }

    return 'generateStatus';
}

function clearStatuses() {
    statusIds.forEach((statusId) => {
        const status = document.getElementById(statusId);
        status.textContent = '';
        status.className = 'status';
    });
}

function clearKeyOutputs() {
    setValue('publicKey', '');
    setValue('privateKey', '');
    setValue('revocationCertificate', '');
}

function setStatus(statusId, message, type) {
    const status = document.getElementById(statusId);
    status.textContent = message;
    status.className = `status ${type}`;
}

function getValue(elementId) {
    return document.getElementById(elementId).value;
}

function setValue(elementId, value) {
    document.getElementById(elementId).value = value;
}

function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
