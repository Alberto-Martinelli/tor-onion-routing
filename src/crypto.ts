import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // DONE implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.

  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true, // key extractable
    ["encrypt", "decrypt"]
  );

  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey};
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
    // DONE implement this function to return a base64 string version of a public key
    const arraybuf = await webcrypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(arraybuf);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // DONE implement this function to return a base64 string version of a private key
  if (key === null) {
    throw new Error("The provided key is null.");
  }
  const arrayBuffer = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(arrayBuffer);
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // DONE implement this function to go back from the result of the exportPubKey function to it's native crypto key object
  const arrbuff = base64ToArrayBuffer(strKey);
  const cryptoKey = await webcrypto.subtle.importKey(
    "spki",
    arrbuff,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );

  return cryptoKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // DONE implement this function to go back from the result of the exportPrvKey function to it's native crypto key object
  const arrbuff = base64ToArrayBuffer(strKey);
  const cryptoKey = await webcrypto.subtle.importKey(
    "pkcs8",
    arrbuff,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );

  return cryptoKey;
  // remove this
  return {} as any;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // DONE implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function
  const messageArrayBuffer = base64ToArrayBuffer(b64Data);
  const publicKey = await importPubKey(strPublicKey);
  const encryptedBuffer = await webcrypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    messageArrayBuffer
  );
  return arrayBufferToBase64(encryptedBuffer);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // DONE implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function
  const messageArrayBuffer = base64ToArrayBuffer(data);
  const encryptedBuffer = await webcrypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    messageArrayBuffer
  );
  return arrayBufferToBase64(encryptedBuffer);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // DONE implement this function using the crypto package to generate a symmetric key.
  //      the key should be used for both encryption and decryption. Make sure the
  //      keys are extractable.
  const key = await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256,
    },
    true, // key extractable
    ["encrypt", "decrypt"] // The key will be used for encryption and decryption
  );

  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // DONE implement this function to return a base64 string version of a symmetric key
  const arrayBuffer = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(arrayBuffer);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // DONE implement this function to go back from the result of the exportSymKey function to it's native crypto key object
  const arrayBuffer = base64ToArrayBuffer(strKey);
  const key = await webcrypto.subtle.importKey(
    "raw",
    arrayBuffer,
    {
      name: "AES-CBC",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );

  return key;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // DONE implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder

  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  // 2. Genera un IV casuale (16 byte per AES-CBC)
  const iv = crypto.getRandomValues(new Uint8Array(16));

  // 3. Cripta i dati usando AES-CBC
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "AES-CBC", // Algoritmo di criptazione
      iv: iv, // Initial Vector (16 byte)
    },
    key, // La chiave simmetrica
    encodedData // I dati da criptare (come Uint8Array)
  );

  // 4. Converte i dati criptati (ArrayBuffer) in una stringa Base64
  const encryptedBase64 = arrayBufferToBase64(encryptedData);

  // Ritorna la stringa Base64 con i dati criptati e l'IV (anch'esso in Base64)
  return `${arrayBufferToBase64(iv.buffer)}:${encryptedBase64}`;
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // DONE implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format
  const keyBuffer = base64ToArrayBuffer(strKey);

  // 2. Importa la chiave simmetrica in formato CryptoKey
  const key = await webcrypto.subtle.importKey(
    "raw", // La chiave è in formato raw (ArrayBuffer)
    keyBuffer, // La chiave come ArrayBuffer
    {
      name: "AES-CBC", // Algoritmo di cifratura simmetrica
    },
    true, // La chiave è estraibile
    ["decrypt"] // Operazione consentita: decriptare
  );

  // 3. Suddividi la stringa cifrata in IV e dati cifrati
  const [ivBase64, encryptedBase64] = encryptedData.split(":");

  // 4. Converti l'IV e i dati cifrati da Base64 a ArrayBuffer
  const iv = base64ToArrayBuffer(ivBase64);
  const encryptedMessage = base64ToArrayBuffer(encryptedBase64);

  // 5. Decripta i dati usando AES-CBC
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: iv, // L'IV usato per la cifratura
    },
    key, // La chiave simmetrica
    encryptedMessage // I dati cifrati
  );

  // 6. Decodifica i dati decriptati in una stringa
  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}
