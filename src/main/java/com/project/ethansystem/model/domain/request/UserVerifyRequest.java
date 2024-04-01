package com.project.ethansystem.model.domain.request;

import lombok.Data;

import java.io.Serializable;

@Data
public class UserVerifyRequest implements Serializable {
    private String userAccount;

    private String verificationCode;
}
