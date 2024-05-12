package com.project.ethansystem.service;

import com.project.ethansystem.model.domain.User;
import com.baomidou.mybatisplus.extension.service.IService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
* @author strivedd
* @description 针对表【user(用户)】的数据库操作Service
* @createDate 2024-03-15 00:17:30
*/
public interface UserService extends IService<User> {
    Long userRegister(String userAccount, String password, String verifyPassword, String userEmail, String inviteCode);

    boolean userRegister(User user);

    User userLogin(String userAccount, String password, HttpServletRequest request);

    User userUpdate(User user, HttpServletRequest request);

    boolean isAdmin(HttpServletRequest request);

    User getSafetyUser(User user);

    boolean userLogout(HttpServletRequest request);
}
