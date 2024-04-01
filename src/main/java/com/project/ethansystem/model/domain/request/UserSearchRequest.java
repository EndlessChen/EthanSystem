package com.project.ethansystem.model.domain.request;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class UserSearchRequest implements Serializable {
    private Long userId;

    private String username;

    private Integer userSex;

    private String userEmail;

    private String userRole;

    private Integer userStatus;
}
