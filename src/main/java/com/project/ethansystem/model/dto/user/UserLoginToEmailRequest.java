package com.project.ethansystem.model.dto.user;

import lombok.Data;

@Data
public class UserLoginToEmailRequest {
    private String userEmail;
    private String verificationCode;
}
