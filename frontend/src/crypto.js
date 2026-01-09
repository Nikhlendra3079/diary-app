import CryptoJS from 'crypto-js';

// Encrypt data using the password as the key
export const encryptData = (text, password) => {
  if (!text) return "";
  return CryptoJS.AES.encrypt(text, password).toString();
};

// Decrypt data
export const decryptData = (ciphertext, password) => {
  if (!ciphertext) return "";
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, password);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (e) {
    return "[Decryption Failed - Wrong Password?]";
  }
};