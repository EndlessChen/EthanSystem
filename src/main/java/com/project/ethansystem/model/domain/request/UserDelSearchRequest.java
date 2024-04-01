package com.project.ethansystem.model.domain.request;

import lombok.Data;
import java.io.Serializable;

@Data
public class UserDelSearchRequest implements Serializable {
    private Long userId;
    private String username;
}
