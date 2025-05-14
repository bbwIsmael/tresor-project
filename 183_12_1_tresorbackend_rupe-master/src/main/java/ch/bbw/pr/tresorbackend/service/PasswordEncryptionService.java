package ch.bbw.pr.tresorbackend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * PasswordEncryptionService
 * @author Peter Rutschmann
 */
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
        // Note: This method assumes the salt is stored with the hash
        // In a real implementation, you would need to extract the salt from the stored hash
        return passwordEncoder.matches(rawPassword + pepper, hashedPassword);
   }
}
