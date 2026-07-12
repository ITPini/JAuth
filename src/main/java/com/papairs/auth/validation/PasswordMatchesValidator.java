package com.papairs.auth.validation;

import com.papairs.auth.dto.request.ChangePasswordRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, ChangePasswordRequest> {

    @Override
    public boolean isValid(ChangePasswordRequest request, ConstraintValidatorContext context) {
        if (request == null || request.newPassword() == null || request.confirmPassword() == null) {
            return true;
        }
        return request.isNewPasswordConfirmed();
    }
}
