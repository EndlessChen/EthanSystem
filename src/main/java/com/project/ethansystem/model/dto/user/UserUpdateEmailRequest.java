package com.project.ethansystem.model.dto.user;

import lombok.Data;

@Data
public class UserUpdateEmailRequest {
    private Long userId;
    private String userEmail;
    private String verificationCode;
}
