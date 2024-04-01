package com.project.ethansystem.utils;

import com.project.ethansystem.common.BaseResponse;
import com.project.ethansystem.common.ErrorCode;

/**
 * 返回工具类
 * @author Ethan
 */
public class ResultUtils {
    /**
     * 成功
     * @param data 数据
     * @return 通用返回对象
     * @param <T> 泛型
     */
    public static <T> BaseResponse<T> success(T data) {
        return new BaseResponse<>(0, data, "success!");
    }

    /**
     * 成功
     * @param data 数据
     * @param message 自定义返回信息
     * @return 通用返回对象
     * @param <T> 泛型
     */
    public static <T> BaseResponse<T> success(T data, String message) {
        return new BaseResponse<>(0, data, message);
    }

    /**
     * 失败
     * @param errorCode 错误码对象
     * @return 通用返回对象
     * @param <T> 泛型
     */
    public static <T> BaseResponse<T> error(ErrorCode errorCode) {
        return new BaseResponse<>(errorCode.getCode(), errorCode.getMessage());
    }

    /**
     * 失败
     * @param errorCode 业务错误码对象
     * @param message 错误消息
     * @return 通用返回对象
     * @param <T> 泛型
     */
    public static <T> BaseResponse<T> error(ErrorCode errorCode, String message) {
        return new BaseResponse<>(errorCode.getCode(), message);
    }

    /**
     * 失败
     * @param code 业务错误码
     * @return 通用返回对象
     * @param <T> 泛型
     */
    public static <T> BaseResponse<T> error(Integer code, String message) {
        return new BaseResponse<>(code, message);
    }
}
