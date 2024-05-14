package com.project.ethansystem.model.dto.user;

import lombok.Data;

import java.io.Serializable;

@Data
public class UserSearchRequest implements Serializable {
    private Long userId;

    private String username;

    private Integer userSex;

    private String userEmail;

    private String userRole;

    private Integer userStatus;
}
