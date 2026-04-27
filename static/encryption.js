// Simple message encryption using Web Crypto API
// Messages are encrypted using AES-GCM with a room-based key

class MessageEncryption {
  static async deriveKey(roomId, password = '') {
    // Derive a consistent key from room ID and optional password
    const material = await window.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(`${roomId}:${password}`),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('vaibgram-salt'),
        iterations: 100000,
      },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  static async encrypt(message, roomId, password = '') {
    try {
      const key = await this.deriveKey(roomId, password);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      const encodedMessage = new TextEncoder().encode(message);
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encodedMessage
      );

      // Combine IV + encrypted data + version byte
      const combined = new Uint8Array(1 + iv.length + encrypted.byteLength);
      combined[0] = 1; // Version byte
      combined.set(iv, 1);
      combined.set(new Uint8Array(encrypted), 1 + iv.length);

      // Convert to base64 for transmission
      return btoa(String.fromCharCode(...combined));
    } catch (error) {
      console.error('Encryption error:', error);
      return null;
    }
  }

  static async decrypt(encryptedMessage, roomId, password = '') {
    try {
      if (!encryptedMessage || typeof encryptedMessage !== 'string') {
        return encryptedMessage; // Return as-is if not encrypted
      }

      // Decode from base64
      const combined = new Uint8Array(
        atob(encryptedMessage)
          .split('')
          .map(c => c.charCodeAt(0))
      );

      if (combined.length < 13 || combined[0] !== 1) {
        return encryptedMessage; // Return as-is if not our encrypted format
      }

      const iv = combined.slice(1, 13);
      const ciphertext = combined.slice(13);

      const key = await this.deriveKey(roomId, password);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error('Decryption error:', error);
      return encryptedMessage; // Return original if decryption fails
    }
  }

  // Optional: Encrypt URLs/attachments metadata
  static async encryptMetadata(metadata, roomId, password = '') {
    try {
      return await this.encrypt(JSON.stringify(metadata), roomId, password);
    } catch (error) {
      console.error('Metadata encryption error:', error);
      return null;
    }
  }

  static async decryptMetadata(encrypted, roomId, password = '') {
    try {
      const decrypted = await this.decrypt(encrypted, roomId, password);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Metadata decryption error:', error);
      return null;
    }
  }

  // Check if a message is encrypted
  static isEncrypted(message) {
    if (!message || typeof message !== 'string') return false;
    try {
      const combined = new Uint8Array(
        atob(message)
          .split('')
          .map(c => c.charCodeAt(0))
      );
      return combined.length >= 13 && combined[0] === 1;
    } catch {
      return false;
    }
  }
}

// Make available globally
window.MessageEncryption = MessageEncryption;
