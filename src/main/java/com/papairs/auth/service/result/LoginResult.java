package com.papairs.auth.service.result;

import com.papairs.auth.model.User;

public record LoginResult(SessionCreationResult session, User user) {}
