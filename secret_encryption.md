# Secret Encryption: Essence of Encryption Methods & Unique Key Generation

## 1. Essence of Encryption Methods

### Symmetric Encryption (AES)
- **AES (Advanced Encryption Standard)** is a widely used symmetric encryption algorithm.
- It uses the same key for both encryption and decryption.
- AES operates on fixed-size blocks (128 bits) and supports key sizes of 128, 192, or 256 bits.
- **Initialization Vector (IV):**
  - A random value used to ensure that encrypting the same plaintext twice produces different ciphertexts.
  - IV should be unique for each encryption and can be stored alongside the ciphertext (not secret).
- **Modes of Operation:**
  - Commonly used mode: CBC (Cipher Block Chaining) or GCM (Galois/Counter Mode).
  - CBC requires IV; GCM provides authentication as well as encryption.

### Why Use AES?
- Fast and secure for large data.
- Well-supported in Java and other languages.
- Resistant to known cryptographic attacks when used with proper key and IV management.

## 2. Essence of Unique Key Generation

### Key Derivation
- **Why?**
  - User passwords are not suitable as encryption keys (too short, low entropy).
  - Key derivation functions (KDFs) transform a password into a strong, fixed-length key.

- **How?**
  - Use a KDF like PBKDF2, bcrypt, or scrypt.
  - Combine the user's password with a unique salt (random value).
  - The salt ensures that the same password produces different keys for different users or secrets.
  - Example in Java: `SecretKeyFactory` with PBKDF2.

### Salt
- A random value unique per user (or per secret).
- Stored with the encrypted data or user record.
- Not secret, but must be unique and unpredictable.

### Initialization Vector (IV)
- Random value generated for each encryption operation.
- Ensures ciphertext uniqueness even if the same data and key are used.
- Appended to the ciphertext for later decryption.

### Summary Example
1. User provides password.
2. Generate or retrieve salt.
3. Derive encryption key using password + salt via PBKDF2.
4. Generate random IV.
5. Encrypt data with AES using derived key and IV.
6. Store ciphertext (with IV and salt if needed).

---

**References:**
- [Baeldung: Java AES Encryption/Decryption](https://www.baeldung.com/java-aes-encryption-decryption)
- [OWASP: Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## 3. Essence of Implementation in This Project

- **Key Derivation:**
  - For each user, a unique random salt is generated and stored in the user table during registration. **The salt must never be empty.**
  - When encrypting or decrypting a secret, the user's password and their salt are combined using PBKDF2 to derive a strong AES key.
  - If the salt is missing (e.g., for users created before this implementation), encryption will fail with an error: `the salt parameter must not be empty`. In this case, delete and re-register the user to ensure a valid salt is present.

- **Encryption/Decryption:**
  - The `EncryptUtil` class handles AES encryption/decryption in CBC mode with PKCS5 padding.
  - A random IV is generated for each encryption and prepended to the ciphertext (all Base64 encoded).
  - The same process is used for decryption: extract IV, derive key, decrypt.

- **Controller Logic:**
  - When a secret is created, the backend receives the user's password and email, retrieves the salt, derives the key, and encrypts the secret content before storing it.
  - When secrets are retrieved, the backend again derives the key from the provided password and stored salt, and decrypts the content before returning it.

- **Frontend Error Handling:**
  - The frontend now checks the response type before parsing, so backend error messages (including plain text errors) are displayed to the user. This helps with debugging issues like missing salt.

- **Security:**
  - The salt is unique per user and never reused.
  - The password is never stored, only used transiently for key derivation.
  - All sensitive operations are wrapped in try-catch blocks to handle errors gracefully.

- **Troubleshooting:**
  - If you see `Encryption error: the salt parameter must not be empty`, ensure the user was registered after the salt implementation. Delete and re-register the user if necessary.

- **References:**
  - See `EncryptUtil.java` and `SecretController.java` for the core logic. 