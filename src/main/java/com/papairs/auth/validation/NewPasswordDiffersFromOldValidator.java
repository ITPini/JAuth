package com.papairs.auth.validation;

import com.papairs.auth.dto.request.ChangePasswordRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NewPasswordDiffersFromOldValidator implements ConstraintValidator<NewPasswordDiffersFromOld, ChangePasswordRequest> {
    @Override
    public boolean isValid(ChangePasswordRequest request, ConstraintValidatorContext context) {
        if (request == null || request.newPassword() == null || request.oldPassword() == null) {
            return true;
        }
        return request.isNewPasswordDifferent();
    }
}
