# Password Hashing, Salt, and Pepper Documentation

## 1. Password Hashing

### What is Password Hashing?
Password hashing is a one-way function that transforms a password into a fixed-length string of characters. The process is irreversible, meaning you cannot retrieve the original password from the hash.

### Common Hash Algorithms

#### 1. MD5 (Message Digest 5)
- **Output Size**: 128 bits (32 characters)
- **Status**: **Not Recommended** - Vulnerable to collision attacks
- **Example**: `password123` → `482c811da5d5b4bc6d497ffa98491e38`

#### 2. SHA-1 (Secure Hash Algorithm 1)
- **Output Size**: 160 bits (40 characters)
- **Status**: **Not Recommended** - Vulnerable to collision attacks
- **Example**: `password123` → `40bd001563085fc35165329ea1ff5c5ecbdbbeef`

#### 3. SHA-256 (Secure Hash Algorithm 256)
- **Output Size**: 256 bits (64 characters)
- **Status**: **Acceptable** but not ideal for passwords
- **Example**: `password123` → `ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f`

#### 4. bcrypt
- **Output Size**: Variable (60 characters)
- **Status**: **Recommended** for password hashing
- **Features**:
  - Built-in salt
  - Adaptive cost factor
  - Resistant to rainbow table attacks
- **Example**: `password123` → `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy`

#### 5. Argon2
- **Output Size**: Variable
- **Status**: **Highly Recommended** - Winner of 2015 Password Hashing Competition
- **Features**:
  - Memory-hard function
  - Resistant to GPU-based attacks
  - Configurable parameters
- **Example**: `password123` → `$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`

### Best Practices for Password Hashing
1. **Never store plaintext passwords**
2. **Use strong, modern algorithms** (bcrypt, Argon2)
3. **Implement proper salt and pepper**
4. **Use appropriate work factors**
5. **Regularly update hashing algorithms**

## 2. Salt

### What is Salt?
Salt is a random string that is added to a password before hashing. It ensures that identical passwords produce different hashes.

### Benefits of Salting
1. **Prevents Rainbow Table Attacks**
   - Rainbow tables become ineffective as each password has a unique salt
2. **Eliminates Hash Collisions**
   - Same passwords will have different hashes
3. **Increases Security**
   - Makes brute-force attacks more difficult

### Implementation Guidelines
1. **Generate Unique Salt**
   ```java
   SecureRandom random = new SecureRandom();
   byte[] salt = new byte[16];
   random.nextBytes(salt);
   ```

2. **Store Salt with Hash**
   - Store salt alongside the hash
   - Format: `$algorithm$salt$hash`

3. **Salt Length**
   - Minimum: 16 bytes (128 bits)
   - Recommended: 32 bytes (256 bits)

## 3. Pepper

### What is Pepper?
Pepper is a secret value added to all passwords before hashing. Unlike salt, pepper is the same for all users and is stored separately from the hashed passwords.

### Benefits of Pepper
1. **Additional Security Layer**
   - Even if database is compromised, passwords remain protected
2. **Protection Against Rainbow Tables**
   - Makes pre-computed tables useless
3. **Defense in Depth**
   - Complements salt for enhanced security

### Implementation Guidelines
1. **Store Pepper Securely**
   - Keep in environment variables
   - Store in secure configuration management
   - Never in database or code

2. **Pepper Length**
   - Minimum: 32 bytes (256 bits)
   - Recommended: 64 bytes (512 bits)

3. **Implementation Example**
   ```java
   String pepper = System.getenv("PEPPER_KEY");
   String hashedPassword = hash(password + salt + pepper);
   ```

## 4. Combined Implementation

### Best Practice Implementation
```java
public String hashPassword(String password) {
    // Generate salt
    byte[] salt = generateSalt();
    
    // Get pepper from secure storage
    String pepper = getPepper();
    
    // Combine password, salt, and pepper
    String combined = password + Base64.getEncoder().encodeToString(salt) + pepper;
    
    // Hash using Argon2 or bcrypt
    return hashWithAlgorithm(combined);
}
```

### Security Considerations
1. **Algorithm Selection**
   - Use Argon2 or bcrypt
   - Avoid MD5, SHA-1, SHA-256 for passwords

2. **Salt Management**
   - Generate unique salt per user
   - Store salt with hash
   - Use cryptographically secure random generator

3. **Pepper Management**
   - Store separately from database
   - Rotate periodically
   - Use secure key management

4. **Work Factors**
   - Adjust based on hardware capabilities
   - Balance security and performance
   - Regular updates as hardware improves

## 5. Common Vulnerabilities to Avoid

1. **Weak Algorithms**
   - MD5, SHA-1, SHA-256 for passwords
   - Custom hash functions

2. **Insufficient Salt**
   - Short salt length
   - Predictable salt generation
   - Reusing salts

3. **Poor Pepper Implementation**
   - Storing pepper in database
   - Weak pepper generation
   - Infrequent rotation

4. **Implementation Errors**
   - Incorrect concatenation order
   - Missing salt or pepper
   - Weak random number generation

## 6. Testing and Validation

### Password Hash Testing
1. **Verify Hash Generation**
   - Test with known inputs
   - Verify salt uniqueness
   - Check pepper integration

2. **Performance Testing**
   - Measure hash generation time
   - Test with different work factors
   - Verify system load

3. **Security Testing**
   - Attempt common attacks
   - Verify salt/pepper effectiveness
   - Test error handling

## 7. Maintenance and Updates

### Regular Maintenance
1. **Algorithm Updates**
   - Monitor for vulnerabilities
   - Plan for algorithm migration
   - Update work factors

2. **Pepper Rotation**
   - Regular pepper changes
   - Secure key management
   - Minimal service impact

3. **Security Monitoring**
   - Track failed login attempts
   - Monitor for brute force attacks
   - Log security events

## 8. Implementation in Tresor Application

### Current Implementation Details

#### PasswordEncryptionService
```java
@Service
public class PasswordEncryptionService {
    private final BCryptPasswordEncoder passwordEncoder;
    private final String pepper;
    private final SecureRandom secureRandom;

    public PasswordEncryptionService(@Value("${PEPPER_KEY:defaultPepperKey}") String pepper) {
        this.passwordEncoder = new BCryptPasswordEncoder(12); // Using strength of 12
        this.pepper = pepper;
        this.secureRandom = new SecureRandom();
    }

    public String hashPassword(String password) {
        // Generate salt
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        String saltString = Base64.getEncoder().encodeToString(salt);

        // Combine password, salt, and pepper
        String combined = password + saltString + pepper;

        // Hash using bcrypt
        return passwordEncoder.encode(combined);
    }

    public boolean doPasswordMatch(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword + pepper, hashedPassword);
    }
}
```

### Implementation Features

1. **Algorithm Choice**
   - Using BCrypt with strength factor of 12
   - Provides good balance between security and performance
   - Built-in protection against rainbow table attacks

2. **Salt Implementation**
   - 16-byte (128-bit) random salt
   - Generated using `SecureRandom`
   - Base64 encoded for storage
   - Unique per user

3. **Pepper Implementation**
   - Configured via environment variable `PEPPER_KEY`
   - Fallback to default value for development
   - Same pepper used for all users
   - Stored separately from database

4. **Security Measures**
   - Combined use of salt and pepper
   - Strong work factor (12) for bcrypt
   - Secure random number generation
   - Environment-based configuration

### Usage in Application

1. **User Registration**
   ```java
   User user = new User(
       null,
       registerUser.getFirstName(),
       registerUser.getLastName(),
       registerUser.getEmail(),
       passwordService.hashPassword(registerUser.getPassword())
   );
   ```

2. **Password Verification**
   ```java
   boolean isMatch = passwordService.doPasswordMatch(rawPassword, storedHash);
   ```

### Configuration Requirements

1. **Environment Variables**
   - `PEPPER_KEY`: Secret pepper value for password hashing
   - Should be at least 32 bytes (256 bits)
   - Must be kept secure and separate from code

2. **Dependencies**
   - Spring Security Crypto
   - BCrypt implementation

### Security Considerations

1. **Current Implementation**
   - Uses industry-standard bcrypt
   - Implements both salt and pepper
   - Secure random number generation
   - Environment-based configuration

2. **Areas for Improvement**
   - Consider upgrading to Argon2 in future
   - Implement pepper rotation mechanism
   - Add password strength validation
   - Implement rate limiting for login attempts

3. **Maintenance Tasks**
   - Regular pepper rotation
   - Monitor for bcrypt vulnerabilities
   - Update work factor as hardware improves
   - Regular security audits

### Testing Strategy

1. **Unit Tests**
   - Test password hashing
   - Verify salt uniqueness
   - Test password matching
   - Verify pepper integration

2. **Integration Tests**
   - Test with UserController
   - Verify database storage
   - Test login flow
   - Verify error handling

3. **Security Tests**
   - Test against common attacks
   - Verify salt/pepper effectiveness
   - Test error handling
   - Verify configuration security

## Implementation Summary (Current Project)

- **Algorithm:** BCrypt (configurable strength via `application.properties`)
- **Salt:** Automatically generated and stored by BCrypt (no manual storage required)
- **Pepper:** Stored in `application.properties` as `PEPPER_KEY` and appended to the password before hashing
- **Tested:** Registration and login flows have been tested and verified to work

### Implementation Example (Current Project)
```java
// Get pepper from application.properties
@Value("${PEPPER_KEY}")
private String pepper;

public String hashPassword(String password) {
    // Pepper is appended to the password
    String passwordWithPepper = password + pepper;
    // BCrypt handles salt generation and storage internally
    return bCryptPasswordEncoder.encode(passwordWithPepper);
}

public boolean verifyPassword(String rawPassword, String storedHash) {
    // Append pepper to the raw password before verification
    String rawWithPepper = rawPassword + pepper;
    return bCryptPasswordEncoder.matches(rawWithPepper, storedHash);
}
```

- **Salt Handling:** No need to store or retrieve salt manually; BCrypt embeds it in the hash.
- **Pepper Handling:** Pepper is stored in `application.properties` as `PEPPER_KEY` (not as an environment variable).
- **Configuration:**
  - `PEPPER_KEY=yourPepperValue`
  - `PASSWORD_HASH_STRENGTH=12` (example) 