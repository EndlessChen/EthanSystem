package com.project.ethansystem.common;

import lombok.Data;

public enum ErrorCode {
    REQUEST_ERROR(40002, "请求对象为空"),
    PARAMS_ERROR(40000, "请求参数错误"),
    NULL_ERROR(40001, "请求数据为空"),
    NO_LOGIN(40100, "未登陆"),
    NO_AUTH(40100, "无权限"),
    SYSTEM_ERROR(50000, "系统内部异常");

    private final Integer code;
    private final String message;

    ErrorCode(Integer code, String message) {
        this.code = code;
        this.message = message;
    }

    public Integer getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
