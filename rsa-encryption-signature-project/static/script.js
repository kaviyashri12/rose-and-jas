// Enhanced Notification System
function showNotification(message, type = 'success') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notif => notif.remove());
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Add icon based on type
    let icon = '';
    switch(type) {
        case 'success':
            icon = '✅';
            break;
        case 'error':
            icon = '❌';
            break;
        case 'warning':
            icon = '⚠️';
            break;
        case 'info':
            icon = 'ℹ️';
            break;
        default:
            icon = '✅';
    }
    
    notification.innerHTML = `${icon} ${message}`;
    document.body.appendChild(notification);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add slideOutRight animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOutRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(style);

// Copy to clipboard with enhanced feedback
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('📋 Copied to clipboard!', 'success');
    } catch (err) {
        showNotification('Failed to copy', 'error');
    }
}

// Loading state for buttons
function setButtonLoading(button, isLoading) {
    if (isLoading) {
        button.originalText = button.innerHTML;
        button.innerHTML = '<span class="spinner"></span> Processing...';
        button.disabled = true;
    } else {
        button.innerHTML = button.originalText;
        button.disabled = false;
    }
}

// Key Generation
async function generateKeys() {
    const keySize = document.getElementById('keySize').value;
    const resultDiv = document.getElementById('keyResult');
    const generateBtn = event.target;
    
    setButtonLoading(generateBtn, true);
    resultDiv.innerHTML = '<div class="result-content"><span class="spinner"></span> Generating RSA keys... This may take a moment.</div>';
    
    try {
        const response = await fetch('/api/generate_keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key_size: keySize })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`✅ ${data.key_size}-bit RSA keys generated successfully!`, 'success');
            resultDiv.innerHTML = `
                <div class="result-box">
                    <div class="result-title">🔑 Public Key (Temporary - Not Saved)</div>
                    <div class="result-content" id="publicKey">${escapeHtml(data.public_key)}</div>
                    <button class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('publicKey').innerText)">📋 Copy Public Key</button>
                    
                    <div class="result-title" style="margin-top: 1rem;">🔒 Private Key (Temporary - Not Saved)</div>
                    <div class="result-content" id="privateKey">${escapeHtml(data.private_key)}</div>
                    <button class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('privateKey').innerText)">📋 Copy Private Key</button>
                    
                    <div class="alert alert-info" style="margin-top: 1rem;">
                        ⚠️ These keys are temporary. Click "Save Keys Permanently" to store them.
                    </div>
                </div>
            `;
        } else {
            showNotification(data.error || 'Failed to generate keys', 'error');
            resultDiv.innerHTML = `<div class="result-box error">❌ Error: ${data.error}</div>`;
        }
    } catch (error) {
        showNotification(error.message, 'error');
        resultDiv.innerHTML = `<div class="result-box error">❌ Error: ${error.message}</div>`;
    } finally {
        setButtonLoading(generateBtn, false);
    }
}

// Save Keys
async function saveKeys() {
    try {
        const response = await fetch('/api/save_keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification('💾 Keys saved permanently to your account!', 'success');
        } else {
            showNotification(data.error || 'No temporary keys to save', 'warning');
        }
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

// Clear Keys
async function clearKeys() {
    if (confirm('⚠️ Clear temporary keys? (Saved keys will remain in your account)')) {
        try {
            const response = await fetch('/api/clear_keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clear_database: false })
            });
            
            const data = await response.json();
            if (data.success) {
                showNotification('🗑️ Temporary keys cleared!', 'info');
                document.getElementById('keyResult').innerHTML = '';
            }
        } catch (error) {
            showNotification(error.message, 'error');
        }
    }
}

// Clear All Keys
async function clearAllKeys() {
    if (confirm('⚠️ WARNING: This will delete ALL your keys from database! This action cannot be undone. Continue?')) {
        try {
            const response = await fetch('/api/clear_keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clear_database: true })
            });
            
            const data = await response.json();
            if (data.success) {
                showNotification('⚠️ All keys have been deleted from your account!', 'warning');
                document.getElementById('keyResult').innerHTML = '';
                setTimeout(() => location.reload(), 1500);
            }
        } catch (error) {
            showNotification(error.message, 'error');
        }
    }
}

// Encrypt and Sign
async function encryptAndSign() {
    const message = document.getElementById('message').value;
    const receiverUsername = document.getElementById('receiverUsername').value;
    const senderPrivateKey = document.getElementById('senderPrivateKey').value;
    
    if (!message || !receiverUsername || !senderPrivateKey) {
        showNotification('Please fill all fields!', 'warning');
        return;
    }
    
    const resultDiv = document.getElementById('encryptSignResult');
    const encryptBtn = event.target;
    
    setButtonLoading(encryptBtn, true);
    resultDiv.innerHTML = '<div class="result-content"><span class="spinner"></span> Encrypting and signing your message...</div>';
    
    try {
        const response = await fetch('/api/encrypt_sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: message,
                receiver_username: receiverUsername,
                sender_private_key: senderPrivateKey
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`✅ Message sent securely to ${data.receiver}!`, 'success');
            resultDiv.innerHTML = `
                <div class="result-box">
                    <div class="result-title">✅ Message Sent Successfully!</div>
                    <div class="alert alert-success">Message encrypted and signed. Sent to: <strong>${data.receiver}</strong></div>
                    
                    <div class="result-title" style="margin-top: 1rem;">🔐 Encrypted Message</div>
                    <div class="result-content" id="encryptedMsg">${escapeHtml(data.encrypted_message)}</div>
                    <button class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('encryptedMsg').innerText)">📋 Copy Encrypted Message</button>
                    
                    <div class="result-title" style="margin-top: 1rem;">✍️ Digital Signature</div>
                    <div class="result-content" id="signature">${escapeHtml(data.signature)}</div>
                    <button class="btn btn-secondary" onclick="copyToClipboard(document.getElementById('signature').innerText)">📋 Copy Signature</button>
                    
                    <div class="alert alert-info" style="margin-top: 1rem;">
                        📨 Message ID: ${data.message_id}<br>
                        🔢 Message Hash: ${data.message_hash}<br>
                        👤 From: ${data.sender} → To: ${data.receiver}
                    </div>
                </div>
            `;
        } else {
            showNotification(data.error, 'error');
            resultDiv.innerHTML = `<div class="result-box error">❌ Error: ${data.error}</div>`;
        }
    } catch (error) {
        showNotification(error.message, 'error');
        resultDiv.innerHTML = `<div class="result-box error">❌ Error: ${error.message}</div>`;
    } finally {
        setButtonLoading(encryptBtn, false);
    }
}

// Decrypt and Verify
async function decryptAndVerify() {
    const encryptedMessage = document.getElementById('encryptedMessage').value;
    const signature = document.getElementById('signatureInput').value;
    const senderUsername = document.getElementById('senderUsername').value;
    
    if (!encryptedMessage || !signature || !senderUsername) {
        showNotification('Please fill all fields!', 'warning');
        return;
    }
    
    const resultDiv = document.getElementById('decryptVerifyResult');
    const decryptBtn = event.target;
    
    setButtonLoading(decryptBtn, true);
    resultDiv.innerHTML = '<div class="result-content"><span class="spinner"></span> Decrypting and verifying signature...</div>';
    
    try {
        const response = await fetch('/api/decrypt_verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                encrypted_message: encryptedMessage,
                signature: signature,
                sender_username: senderUsername
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            if (data.signature_valid) {
                showNotification(`✅ Signature verified! Message from ${data.sender_username} is authentic.`, 'success');
            } else {
                showNotification(`⚠️ Invalid signature! This message may be tampered.`, 'warning');
            }
            
            const validBadge = data.signature_valid 
                ? `<span class="badge badge-success" style="font-size: 1rem;">✓ SIGNATURE VALID - Verified: ${data.sender_username}</span>`
                : `<span class="badge badge-danger" style="font-size: 1rem;">✗ INVALID SIGNATURE - Cannot Verify Sender</span>`;
            
            resultDiv.innerHTML = `
                <div class="result-box">
                    <div class="result-title">📄 Decrypted Message</div>
                    <div class="result-content" style="background: #f0fdf4; font-size: 1.1rem;">${escapeHtml(data.decrypted_message)}</div>
                    
                    <div class="result-title" style="margin-top: 1rem;">✅ Signature Verification</div>
                    <div class="result-content">${validBadge}</div>
                    
                    ${data.signature_valid ? `
                        <div class="alert alert-success" style="margin-top: 1rem;">
                            <strong>✅ Identity Verified!</strong><br>
                            This message was definitely sent by: <strong>${data.sender_username}</strong><br>
                            The digital signature has been cryptographically verified.
                        </div>
                    ` : `
                        <div class="alert alert-danger" style="margin-top: 1rem;">
                            <strong>⚠️ Security Warning!</strong><br>
                            This message may have been tampered with or is from an imposter!<br>
                            Do not trust the contents of this message.
                        </div>
                    `}
                </div>
            `;
        } else {
            showNotification(data.error, 'error');
            resultDiv.innerHTML = `
                <div class="result-box error">
                    <strong>❌ Decryption Failed</strong><br>
                    ${escapeHtml(data.error)}
                    <div class="alert alert-warning" style="margin-top: 1rem;">
                        <strong>💡 Troubleshooting Tips:</strong><br>
                        • Make sure you have generated and saved your keys<br>
                        • Verify the sender's username is correct<br>
                        • Ensure this message was encrypted for you<br>
                        • Try regenerating your keys on the Generate Keys page
                    </div>
                </div>
            `;
        }
    } catch (error) {
        showNotification(error.message, 'error');
        resultDiv.innerHTML = `<div class="result-box error">❌ Error: ${error.message}</div>`;
    } finally {
        setButtonLoading(decryptBtn, false);
    }
}

// Load message from dropdown
function loadSelectedMessage() {
    const select = document.getElementById('messageSelect');
    const selectedOption = select.options[select.selectedIndex];
    
    if (selectedOption && selectedOption.value) {
        const encryptedMsg = selectedOption.getAttribute('data-encrypted');
        const signature = selectedOption.getAttribute('data-signature');
        const sender = selectedOption.getAttribute('data-sender');
        
        if (encryptedMsg && signature && sender) {
            document.getElementById('encryptedMessage').value = encryptedMsg;
            document.getElementById('signatureInput').value = signature;
            document.getElementById('senderUsername').value = sender;
            showNotification(`📨 Loaded message from ${sender}`, 'info');
        }
    }
}

// Clear form
function clearForm() {
    const textareas = document.querySelectorAll('textarea');
    const inputs = document.querySelectorAll('input[type="text"]');
    
    textareas.forEach(textarea => textarea.value = '');
    inputs.forEach(input => input.value = '');
    
    const resultDivs = document.querySelectorAll('#encryptSignResult, #decryptVerifyResult, #keyResult');
    resultDivs.forEach(div => div.innerHTML = '');
    
    showNotification('Form cleared successfully', 'info');
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Check key status
async function checkKeyStatus() {
    try {
        const response = await fetch('/api/check_keys');
        const data = await response.json();
        
        const statusDiv = document.getElementById('keyStatus');
        if (statusDiv) {
            if (data.has_private_key) {
                statusDiv.innerHTML = `
                    <div class="alert alert-success">
                        ✅ <strong>Key Status:</strong> You have valid ${data.key_size}-bit RSA keys! Ready to decrypt messages.
                    </div>
                `;
            } else {
                statusDiv.innerHTML = `
                    <div class="alert alert-warning">
                        ⚠️ <strong>No Keys Found!</strong> Please go to <a href="/generate_keys">Generate Keys</a> page to create your key pair first.
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error checking keys:', error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Add loading spinner CSS if not exists
    if (!document.querySelector('#spinner-style')) {
        const spinnerStyle = document.createElement('style');
        spinnerStyle.id = 'spinner-style';
        spinnerStyle.textContent = `
            .spinner {
                display: inline-block;
                width: 16px;
                height: 16px;
                border: 2px solid rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                border-top-color: white;
                animation: spin 0.6s linear infinite;
                margin-right: 8px;
            }
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(spinnerStyle);
    }
    
    // Check key status on decrypt page
    if (window.location.pathname === '/decrypt_verify') {
        checkKeyStatus();
    }
});