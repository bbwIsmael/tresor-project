package ch.bbw.pr.tresorbackend.model;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * LoginUser
 * Model for user login requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser {
    @NotEmpty(message = "Email is required.")
    private String email;

    @NotEmpty(message = "Password is required.")
    private String password;
} 