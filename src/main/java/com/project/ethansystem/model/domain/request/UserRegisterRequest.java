package com.project.ethansystem.model.domain.request;

import lombok.Data;

import java.io.Serializable;

@Data
public class UserRegisterRequest implements Serializable {
    private String userAccount;

    private String userPassword;

    private String verifyPassword;

    private String inviteCode;
}
