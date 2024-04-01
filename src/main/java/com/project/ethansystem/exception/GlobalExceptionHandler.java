package com.project.ethansystem.exception;

import com.project.ethansystem.common.BaseResponse;
import com.project.ethansystem.common.ErrorCode;
import com.project.ethansystem.utils.ResultUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler(BusinessException.class)
    public BaseResponse<?> businessExceptionHandler(BusinessException exception) {
        log.info("---------------------------------------------------------");
        log.info("BusinessException: " + exception.getMessage());
        log.info("Error details: " + exception);
        log.info("---------------------------------------------------------");
        return ResultUtils.error(exception.getCode(), exception.getMessage());
    }

    @ExceptionHandler(RuntimeException.class)
    public BaseResponse<?> runtimeExceptionHandler(RuntimeException exception) {
        log.info("---------------------------------------------------------");
        log.info("RuntimeException: " + exception.getMessage());
        log.info("Error details: " + exception);
        log.info("---------------------------------------------------------");
        return ResultUtils.error(ErrorCode.SYSTEM_ERROR);
    }
}
