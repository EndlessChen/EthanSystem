package com.project.ethansystem.model.dto.user;

import lombok.Data;

import java.io.Serializable;

@Data
public class UserRegisterRequest implements Serializable {
    private String userAccount;

    private String userPassword;

    private String verifyPassword;

    private String userEmail;

    private String inviteCode;
}
