package com.project.ethansystem.constant;

/**
 * 用户常量属性
 * @author Ethan
 */
public interface UserConstant {
    // 用户密码的盐值
    String SALT = "Ethan";

    // 因为目前是单机登陆，所以用常量表示登陆状态
    String LOGIN_STATUS = "userLogin";

    // 普通用户角色
    String USER_ROLE = "user";

    // 管理员用户角色
    String ADMIN_ROLE = "admin";

    // 用户状态正常
    Integer USER_NORMAL = 1;

    // 用户状态异常
    Integer USER_ABNORMAL = 0;
}
