package com.project.ethansystem.common;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import lombok.Data;

import java.io.Serializable;

@Data
public class BaseResponse<T> implements Serializable {
    private Integer code;

    private T data;

    private String message;

    public BaseResponse(Integer code, T data) {
        this(code, data, "");
    }

    public BaseResponse(Integer code, String message) {
        this(code, null, message);
    }

    public BaseResponse(ErrorCode errorCode) {
        this(errorCode.getCode(), errorCode.getMessage());
    }

    public BaseResponse(ErrorCode errorCode, String message) {
        this(errorCode.getCode(), message);
    }

    public BaseResponse(Integer code, T data, String message) {
        this.code = code;
        this.data = data;
        this.message = message;
    }
}
