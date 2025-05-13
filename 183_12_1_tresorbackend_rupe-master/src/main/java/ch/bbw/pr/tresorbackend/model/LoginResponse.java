package ch.bbw.pr.tresorbackend.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * LoginResponse
 * Model for login response
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String message;
    private Long userId;
} 