package com.project.ethansystem.service;

import com.project.ethansystem.model.dto.user.UserRegisterRequest;
import com.project.ethansystem.model.dto.user.UserUpdateEmailRequest;
import com.project.ethansystem.model.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

/**
* @author strivedd
* @description 针对表【user(用户)】的数据库操作Service
* @createDate 2024-03-15 00:17:30
*/
public interface UserService extends IService<User> {
    Long userRegister(String userAccount, String password, String verifyPassword, String userEmail, String verificationCode);

    boolean userRegister(User user);

    User userLogin(String userAccount, String password, HttpServletRequest request);

    User userLoginFromEmail(String userEmail, String verificationCode, HttpServletRequest request);

    List<User> userSearch(User user);

    User userUpdate(User user, HttpServletRequest request);

    User userUpdateEmail(UserUpdateEmailRequest userUpdateEmailRequest, HttpServletRequest request);

    boolean isAdmin(HttpServletRequest request);

    User getSafetyUser(User user);

    boolean userLogout(HttpServletRequest request);

    boolean userAccountVerify(String userAccount);

    boolean userEmailVerify(String userEmail);

    void sendEmail(String userEmail, String userAccount);

    void verifyEmailCode(String userAccount, String verificationCode);

    void userResetPassword(String userAccount, String userPassword);

    boolean userExists(@RequestBody UserRegisterRequest userRegisterRequest);
}
