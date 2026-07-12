package com.papairs.auth.dto.request;

import com.papairs.auth.validation.PasswordMatches;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@PasswordMatches
public record ChangePasswordRequest (
    @NotBlank(message = "Old Password is required")
    String oldPassword,
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be 8-128 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must contain at least: one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)"
    )
    String newPassword,
    @NotBlank(message = "Confirm Password is required")
    String confirmPassword
) {
    /**
     * Check if new password matches confirm password
     * @return true if matches, false otherwise
     */
    public boolean isNewPasswordConfirmed() {
        return this.newPassword.equals(this.confirmPassword);
    }

    /**
     * Check if new password is different from old password
     * @return true if different, false otherwise
     */
    public boolean isNewPasswordDifferent() {
        return !this.newPassword.equals(this.oldPassword);
    }
}
