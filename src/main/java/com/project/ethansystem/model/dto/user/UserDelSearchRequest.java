package com.project.ethansystem.model.dto.user;

import lombok.Data;
import java.io.Serializable;

@Data
public class UserDelSearchRequest implements Serializable {
    private Long userId;
    private String username;
}
