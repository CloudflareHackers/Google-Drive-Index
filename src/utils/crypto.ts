/**
 * Cryptographic Utilities
 * Handles encryption, decryption, and integrity verification
 * @version 3.0.0
 */

import { config } from '../config';

// ============================================================================
// AES-CBC Encryption/Decryption
// ============================================================================

/**
 * Derive a proper 256-bit AES key from an arbitrary-length string
 * Uses SHA-256 to always produce exactly 32 bytes (256 bits)
 */
async function deriveAESKey(keyString: string, usage: KeyUsage[]): Promise<CryptoKey> {
  const keyData = new TextEncoder().encode(keyString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
  return crypto.subtle.importKey(
    'raw',
    hashBuffer,
    'AES-CBC',
    false,
    usage
  );
}

/**
 * Encrypt a string using AES-CBC
 * @param plaintext - The string to encrypt
 * @returns Base64 encoded encrypted string
 */
export async function encryptString(plaintext: string): Promise<string> {
  const key = await deriveAESKey(config.crypto_base_key, ['encrypt']);

  const encodedData = new TextEncoder().encode(plaintext);
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: config.encrypt_iv
    },
    key,
    encodedData
  );

  // Convert to base64
  const encryptedArray = new Uint8Array(encryptedData);
  const encryptedString = btoa(
    Array.from(encryptedArray, byte => String.fromCharCode(byte)).join('')
  );

  return encryptedString;
}

/**
 * Decrypt a base64 encoded AES-CBC encrypted string
 * @param encryptedString - Base64 encoded encrypted string
 * @returns Decrypted plaintext string
 */
export async function decryptString(encryptedString: string): Promise<string> {
  const key = await deriveAESKey(config.crypto_base_key, ['decrypt']);

  const encryptedBytes = Uint8Array.from(
    atob(encryptedString),
    char => char.charCodeAt(0)
  );

  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv: config.encrypt_iv
    },
    key,
    encryptedBytes
  );

  return new TextDecoder().decode(decryptedData);
}

// ============================================================================
// HMAC Integrity
// ============================================================================

/**
 * Generate HMAC-SHA256 integrity hash
 * @param data - Data to hash
 * @param key - Optional custom key (defaults to config key)
 * @returns Hex encoded HMAC hash
 */
export async function generateIntegrity(
  data: string,
  key: string = config.hmac_base_key
): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const hmacBuffer = await crypto.subtle.sign('HMAC', hmacKey, dataBuffer);

  // Convert to hex string
  const hmacArray = Array.from(new Uint8Array(hmacBuffer));
  const hmacHex = hmacArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

  return hmacHex;
}

/**
 * Verify HMAC integrity
 * @param data - Original data
 * @param expectedHash - Expected HMAC hash
 * @param key - Optional custom key
 * @returns True if integrity check passes
 */
export async function verifyIntegrity(
  data: string,
  expectedHash: string,
  key?: string
): Promise<boolean> {
  const calculatedHash = await generateIntegrity(data, key);
  return calculatedHash === expectedHash;
}

// ============================================================================
// JWT Token Handling (for Service Accounts)
// ============================================================================

const JWT_HEADER = {
  alg: 'RS256',
  typ: 'JWT'
};

/**
 * Import RSA private key from PEM format
 */
async function importPrivateKey(pemKey: string): Promise<CryptoKey> {
  // Remove PEM headers and decode base64
  const pemContent = pemKey
    .split('\n')
    .map(s => s.trim())
    .filter(l => l.length && !l.startsWith('---'))
    .join('');

  const binaryDer = Uint8Array.from(atob(pemContent), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

/**
 * Create RSA signature
 */
async function createSignature(text: string, key: CryptoKey): Promise<ArrayBuffer> {
  const textBuffer = new TextEncoder().encode(text);
  return crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, textBuffer);
}

/**
 * Convert ArrayBuffer to URL-safe base64
 */
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
}

/**
 * Generate GCP JWT token for service account authentication
 * @param serviceAccount - Service account configuration
 * @returns JWT token string
 */
export async function generateGCPToken(serviceAccount: {
  client_email: string;
  private_key: string;
}): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);

  const payload = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/drive',
    aud: 'https://oauth2.googleapis.com/token',
    exp: iat + 3600,
    iat: iat
  };

  const encHeader = btoa(JSON.stringify(JWT_HEADER))
    .replace(/\//g, '_')
    .replace(/\+/g, '-')
    .replace(/=/g, '');

  const encPayload = btoa(JSON.stringify(payload))
    .replace(/\//g, '_')
    .replace(/\+/g, '-')
    .replace(/=/g, '');

  const key = await importPrivateKey(serviceAccount.private_key);
  const signature = await createSignature(`${encHeader}.${encPayload}`, key);

  return `${encHeader}.${encPayload}.${arrayBufferToBase64Url(signature)}`;
}

// ============================================================================
// Download Link Generation
// ============================================================================

/**
 * Generate an encrypted, time-limited download link
 * @param fileId - Google Drive file ID
 * @param userIp - Optional user IP for IP-locked links
 * @returns Encrypted download URL path
 */
export async function generateDownloadLink(
  fileId: string,
  userIp?: string
): Promise<string> {
  const encryptedId = await encryptString(fileId);
  const expiry = Date.now() + 1000 * 60 * 60 * 24 * config.auth.file_link_expiry;
  const encryptedExpiry = await encryptString(expiry.toString());

  let url: string;
  let integrityData: string;

  if (config.auth.enable_ip_lock && userIp) {
    integrityData = `${fileId}|${expiry}|${userIp}`;
    const integrity = await generateIntegrity(integrityData);
    const encryptedIp = await encryptString(userIp);
    url = `/download.aspx?file=${encodeURIComponent(encryptedId)}&expiry=${encodeURIComponent(encryptedExpiry)}&ip=${encodeURIComponent(encryptedIp)}&mac=${encodeURIComponent(integrity)}`;
  } else {
    integrityData = `${fileId}|${expiry}`;
    const integrity = await generateIntegrity(integrityData);
    url = `/download.aspx?file=${encodeURIComponent(encryptedId)}&expiry=${encodeURIComponent(encryptedExpiry)}&mac=${encodeURIComponent(integrity)}`;
  }

  return url;
}

/**
 * Verify and extract data from an encrypted download link
 * @param encryptedFileId - Encrypted file ID
 * @param encryptedExpiry - Encrypted expiry timestamp
 * @param mac - HMAC integrity hash
 * @param userIp - Optional user IP for verification
 * @returns Object with fileId if valid, or null if invalid
 */
export async function verifyDownloadLink(
  encryptedFileId: string,
  encryptedExpiry: string,
  mac: string,
  userIp?: string
): Promise<{ fileId: string; expiry: number } | null> {
  try {
    const fileId = await decryptString(encryptedFileId);
    const expiry = parseInt(await decryptString(encryptedExpiry), 10);

    // Check expiry
    if (expiry < Date.now()) {
      return null;
    }

    // Verify integrity
    let integrityData: string;
    if (config.auth.enable_ip_lock && userIp) {
      integrityData = `${fileId}|${expiry}|${userIp}`;
    } else {
      integrityData = `${fileId}|${expiry}`;
    }

    const isValid = await verifyIntegrity(integrityData, mac);
    if (!isValid) {
      return null;
    }

    return { fileId, expiry };
  } catch {
    return null;
  }
}

// ============================================================================
// Session Token Generation
// ============================================================================

/**
 * Generate encrypted session token
 * @param username - User's username
 * @param password - User's password (or KV key)
 * @param expiryDays - Number of days until expiry
 * @returns Encrypted session string
 */
export async function generateSessionToken(
  username: string,
  password: string,
  expiryDays: number = config.auth.login_days
): Promise<string> {
  const sessionTime = Date.now() + 86400000 * expiryDays;
  const encryptedUsername = await encryptString(username);
  const encryptedPassword = await encryptString(password);
  const encryptedTime = await encryptString(sessionTime.toString());

  return `${encryptedUsername}|${encryptedPassword}|${encryptedTime}`;
}

/**
 * Parse and validate session token
 * @param sessionToken - Encrypted session token
 * @returns Parsed session data or null if invalid/expired
 */
export async function parseSessionToken(
  sessionToken: string
): Promise<{ username: string; password: string; expiry: number } | null> {
  try {
    const parts = sessionToken.split('|');
    if (parts.length !== 3) {
      return null;
    }

    const username = await decryptString(parts[0]);
    const password = await decryptString(parts[1]);
    const expiry = parseInt(await decryptString(parts[2]), 10);

    // Check if expired
    if (expiry < Date.now()) {
      return null;
    }

    return { username, password, expiry };
  } catch {
    return null;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Decode JWT token (without verification - for reading claims only)
 * @param token - JWT token string
 * @returns Decoded payload
 */
export function decodeJwtToken(token: string): Record<string, unknown> {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );

  return JSON.parse(jsonPayload);
}

/**
 * Generate random hex string
 * @param length - Number of bytes
 * @returns Hex string
 */
export function generateRandomHex(length: number = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate random IV for AES
 * @returns 16-byte Uint8Array
 */
export function generateRandomIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

export default {
  encryptString,
  decryptString,
  generateIntegrity,
  verifyIntegrity,
  generateGCPToken,
  generateDownloadLink,
  verifyDownloadLink,
  generateSessionToken,
  parseSessionToken,
  decodeJwtToken,
  generateRandomHex,
  generateRandomIV
};
