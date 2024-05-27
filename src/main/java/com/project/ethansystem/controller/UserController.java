package com.project.ethansystem.controller;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.project.ethansystem.common.BaseResponse;
import com.project.ethansystem.common.ErrorCode;
import com.project.ethansystem.constant.UserConstant;
import com.project.ethansystem.exception.BusinessException;
import com.project.ethansystem.model.dto.user.*;
import com.project.ethansystem.model.entity.User;
import com.project.ethansystem.model.dto.user.UserVerifyResponse;
import com.project.ethansystem.service.UserService;
import com.project.ethansystem.utils.ResultUtils;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 用户响应处理器
 * @author Ethan Chen
 */

@RestController
@Slf4j
@RequestMapping("/user")
public class UserController {
    @Resource
    private UserService userService;

    /**
     * 用户注册接口
     * @param userRegisterRequest 用户注册 DTO 对象
     * @return 注册成功的用户 id
     */
    @PostMapping("/register")
    public BaseResponse<Long> userRegister(@RequestBody UserRegisterRequest userRegisterRequest) {
        if (userRegisterRequest == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        String userAccount = userRegisterRequest.getUserAccount();;
        String userPassword = userRegisterRequest.getUserPassword();
        String userEmail = userRegisterRequest.getUserEmail();
        String verifyPassword = userRegisterRequest.getVerifyPassword();
        String verificationCode = userRegisterRequest.getVerificationCode();
        if (StringUtils.isAnyBlank(userAccount, userPassword, userEmail, verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能为空");
        Long userId = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, verificationCode);
        return ResultUtils.success(userId);
    }

    /**
     * 用户注册(仅限管理员)
     * @param user 用户对象
     * @param request 原生 Servlet 请求对象
     * @return 布尔值，表示是否成功注册用户
     */
    @Operation(summary = "userRegisterToAdmin")
    @PostMapping("/admin/register")
    public BaseResponse<Boolean> userRegister(@RequestBody User user, HttpServletRequest request) {
        if (user == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        User loginUser = (User) request.getSession().getAttribute(UserConstant.LOGIN_STATUS);
        if (loginUser == null) throw new BusinessException(ErrorCode.NO_AUTH, "用户未登陆");
        if (!loginUser.getUserRole().equals(UserConstant.ADMIN_ROLE)) throw new BusinessException(ErrorCode.NO_AUTH, "无权限操作");
        String userAccount = user.getUserAccount();
        String userPassword = user.getUserPassword();
        Integer userSex = user.getUserSex();
        String userRole = user.getUserRole();
        // 验证数据是否合法
        if (StringUtils.isAnyBlank(userAccount, userPassword, userRole)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        if (userSex != null && userSex != 0 && userSex != 1) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        boolean saveUserStatus = userService.userRegister(user);
        if (!saveUserStatus) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "数据库异常，请稍后再试");
        return ResultUtils.success(Boolean.TRUE);
    }

    /**
     * 用户登陆接口
     * @param userLoginRequest 用户登陆 DTO 对象
     * @param request 原生 Servlet 请求对象
     * @return 登陆成功的用户对象
     */
    @PostMapping("/login")
    public BaseResponse<User> userLogin(@RequestBody UserLoginRequest userLoginRequest, HttpServletRequest request) {
        if (userLoginRequest == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        String userAccount = userLoginRequest.getUserAccount();
        String userPassword = userLoginRequest.getUserPassword();
        if (StringUtils.isAnyBlank(userAccount, userPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能为空");
        User user = userService.userLogin(userAccount, userPassword, request);
        return ResultUtils.success(user);
    }

    /**
     * 用户用邮箱登陆接口
     * @param userLoginRequest 用户登陆 DTO 对象
     * @return 登陆成功的用户对象
     */
    @Operation(summary = "userLoginFromEmail")
    @PostMapping("/login/email")
    public BaseResponse<User> userLogin(@RequestBody UserLoginToEmailRequest userLoginRequest, HttpServletRequest request) {
        if (userLoginRequest == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        String userEmail = userLoginRequest.getUserEmail();
        String verificationCode = userLoginRequest.getVerificationCode();
        if (!userService.userEmailVerify(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户邮箱格式非法");
        if (StringUtils.isAnyBlank(verificationCode, userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能为空");
        User user = userService.userLoginFromEmail(userEmail, verificationCode, request);
        return ResultUtils.success(user);
    }

    /**
     * 用户搜索接口，一般只用 userId 搜索用户(仅限管理员)
     * @param user 用户查询 DTO 对象
     * @param request 原生 Servlet 请求对象
     * @return 查询成功的用户对象
     */
    @PostMapping("/search")
    public BaseResponse<User> userSearch(@RequestBody UserDelSearchRequest user, HttpServletRequest request) {
        if (user == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        // 先获取已登陆的用户信息，如果用户未登陆或者不是管理员，那么就停止查询
        if (!userService.isAdmin(request)) throw new BusinessException(ErrorCode.NO_AUTH);
        Long userId = user.getUserId();
        String username = user.getUsername();
        if (userId == null  && StringUtils.isBlank(username)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能全为空");
        if ((userId != null && userId < 0)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        User targetUser = new User();
        targetUser.setUserId(userId);
        targetUser.setUsername(username);
        User finalUser = userService.userSearch(targetUser).get(0);
        return ResultUtils.success(finalUser);
    }

    /**
     * 用户查询接口，根据用户属性获取多个用户信息(仅限管理员)
     * @param user 用户查询 DTO 对象
     * @param request 原生 Servlet 请求对象
     * @return 查询到的所有用户对象
     */
    @Operation(summary = "userSearchForDetail")
    @PostMapping("/detail/search")
    public BaseResponse<List<User>> userSearch(@RequestBody UserSearchRequest user, HttpServletRequest request) {
        if (user == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        // 先获取已登陆的用户信息，如果用户未登陆或者不是管理员，那么就停止查询
        if (!userService.isAdmin(request)) throw new BusinessException(ErrorCode.NO_AUTH);
        Long userId = user.getUserId();
        String username = user.getUsername();
        Integer userSex = user.getUserSex();
        String userEmail = user.getUserEmail();
        String userRole = user.getUserRole();
        Integer userStatus = user.getUserStatus();
        if (userId == null && userSex == null && userStatus == null && StringUtils.isAllBlank(username, userEmail, userRole)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能全为空");
        if ((userId != null && userId < 0) || (userSex != null && userSex != 0 && userSex != 1) || (userStatus != null && userStatus != 0 && userStatus != 1)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        User targetUser = new User();
        targetUser.setUserId(userId);
        targetUser.setUsername(username);
        targetUser.setUserSex(userSex);
        targetUser.setUserEmail(userEmail);
        targetUser.setUserRole(userRole);
        targetUser.setUserStatus(userStatus);
        return ResultUtils.success(userService.userSearch(targetUser));
    }

    /**
     * 用户删除接口，一般只用 userId 来删除用户(仅限管理员)
     * @param userDelSearchRequest 用户查询 DTO 对象
     * @param request 原生 Servlet 请求对象
     * @return 布尔值，表示是否删除成功
     */
    @PostMapping("/delete")
    public BaseResponse<Boolean> userDelete(@RequestBody UserDelSearchRequest userDelSearchRequest, HttpServletRequest request) {
        if (userDelSearchRequest == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        // 获取已登陆的用户信息，如果用户未登陆或者不是管理员，那么就停止查询
        User loginUser = (User) request.getSession().getAttribute(UserConstant.LOGIN_STATUS);
        if (loginUser == null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户不存在");
        if (!loginUser.getUserRole().equals(UserConstant.ADMIN_ROLE)) throw new BusinessException(ErrorCode.NO_AUTH, "无权限操作");
        // 获取数据并开始操作
        Long userId = userDelSearchRequest.getUserId();
        if (userId == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        User user = userId.equals(loginUser.getUserId()) ? loginUser : userService.getById(userId);
        if (user == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户不存在");
        // 不可以删除管理员的账户
        if (user.getUserRole().equals(UserConstant.ADMIN_ROLE)) throw new BusinessException(ErrorCode.NO_AUTH, "无法删除管理员账户");
        boolean deleteStatus = userService.removeById(user.getUserId());
        return deleteStatus ? ResultUtils.success(Boolean.TRUE) : ResultUtils.error(ErrorCode.SYSTEM_ERROR, "系统内部错误");
    }

    /**
     * 查询用户接口，用来查询数据库中所有用户(仅限管理员)
     * @param request 原生 Servlet 请求对象
     * @return 所有用户对象
     */
    @Operation(summary = "userSearchForAll")
    @GetMapping("/search/all")
    public BaseResponse<List<User>> userSearch(HttpServletRequest request) {
        if (request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        // 先获取已登陆的用户信息，如果用户未登陆或者不是管理员，那么就停止查询
        if (!userService.isAdmin(request)) throw new BusinessException(ErrorCode.NO_AUTH);
        return ResultUtils.success(userService.userSearch(new User()));
    }

    /**
     * 退出登录接口
     * @param request 原生 Servlet 请求对象
     * @return 布尔值，表示是否成功退出登录
     */
    @PostMapping("/logout")
    public BaseResponse<Boolean> userLogout(HttpServletRequest request) {
        if (request == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        boolean status = userService.userLogout(request);
        return ResultUtils.success(status);
    }

    /**
     * 获取登陆用户的接口，根据请求对象获取登陆用户的信息，仅限单点登录
     * @param request 原生 Servlet 请求对象
     * @return 返回已登陆的用户信息
     */
    @GetMapping("/current")
    public BaseResponse<User> getCurrentUser(HttpServletRequest request) {
        if (request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        Object userObject = request.getSession().getAttribute(UserConstant.LOGIN_STATUS);
        User currentUser = (User) userObject;
        if (currentUser == null) throw new BusinessException(ErrorCode.NO_LOGIN);
        Long userId = currentUser.getUserId();
        User latestUser = userService.getById(userId);
        User safeyUser = userService.getSafetyUser(latestUser);
        return ResultUtils.success(safeyUser);
    }

    /**
     * 用户更新接口
     * @param user 用户 DTO 对象
     * @param request 原生 Servlet 请求对象
     * @return 已更新的用户对象
     */
    @PostMapping("/update")
    public BaseResponse<User> userUpdate(@RequestBody User user, HttpServletRequest request) {
        if (user == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户对象为空");
        User safetyUser = userService.userUpdate(user, request);
        return ResultUtils.success(safetyUser);
    }

    /**
     * 用户更新邮箱
     * @param userUpdateEmailRequest 用户更新邮箱所用的 DTO 对象
     * @param request 原生 Servlet 对象
     * @return 更新好之后的用户对象
     */
    @PostMapping("/update/email")
    public BaseResponse<User> userUpdateEmail(@RequestBody UserUpdateEmailRequest userUpdateEmailRequest, HttpServletRequest request) {
        if (userUpdateEmailRequest == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户对象为空");
        Long userId = userUpdateEmailRequest.getUserId();
        String userEmail = userUpdateEmailRequest.getUserEmail();
        String verificationCode = userUpdateEmailRequest.getVerificationCode();
        if (StringUtils.isAnyBlank(userEmail, verificationCode) || Objects.isNull(userId)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        User updateUser = userService.userUpdateEmail(userUpdateEmailRequest, request);
        return ResultUtils.success(updateUser);
    }

    /**
     * 发送验证码接口，用来帮助用户找回密码
     * @param userVerifyRequest 用户验证 DTO 对象
     * @return 用户验证响应 DTO 对象
     */
    @PostMapping("/send/verify")
    public BaseResponse<UserVerifyResponse> userSendVerifyCode(@RequestBody UserVerifyRequest userVerifyRequest) {
        if (userVerifyRequest == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        String userAccount = userVerifyRequest.getUserAccount();
        // 如果用户输入的数据不合法，就直接返回
        if (StringUtils.isBlank(userAccount) || userAccount.length() < 5) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        User currentUser = userService.getOne(queryWrapper);
        // 如果用户或者用户邮箱不存在，也直接返回
        if (currentUser == null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户不存在");
        if (StringUtils.isBlank(currentUser.getUserEmail())) throw new BusinessException(ErrorCode.NULL_ERROR, "用户没有设置邮箱，请联系管理员");
        // 如果用户状态异常，也无法重置密码
        if (currentUser.getUserStatus().equals(UserConstant.USER_ABNORMAL)) throw new BusinessException(ErrorCode.NULL_ERROR, "用户状态异常，请联系管理员");
        // 给用户发送验证码
        userService.sendEmail(currentUser.getUserEmail(), userAccount + UserConstant.RESET_PASSWORD_TOKEN);
        UserVerifyResponse response = new UserVerifyResponse();
        response.setUserAccount(userAccount);
        return ResultUtils.success(response);
    }

    /**
     * 给用邮箱登陆的用户发送验证码
     * @param userLoginRequest 用户请求对象
     * @return 通用返回对象
     */
    @PostMapping("/send/login/code")
    public BaseResponse<Boolean> userLoginVerifyCode(@RequestBody UserLoginRequest userLoginRequest) {
        if (userLoginRequest == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        String userEmail = userLoginRequest.getUserEmail();
        if (StringUtils.isBlank(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户邮箱不能为空");
        boolean emailVerifyResult = userService.userEmailVerify(userEmail);
        if (!emailVerifyResult) throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式有误, 请重新输入");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserEmail, userEmail);
        User currentUser = userService.getOne(queryWrapper);
        if (currentUser == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户不存在!");
        userService.sendEmail(userEmail, currentUser.getUserAccount() + UserConstant.LOGIN_TOKEN);
        return ResultUtils.success(Boolean.TRUE);
    }

    /**
     * 用户修改邮箱时发验证码确认
     * @param userUpdateEmailRequest DTO 对象
     * @param request 原生 Servlet 请求
     * @return 通用对象
     */
    @PostMapping("/send/email/code")
    public BaseResponse<Boolean> userUpdateEmailVerifyCode(@RequestBody UserUpdateEmailRequest userUpdateEmailRequest, HttpServletRequest request) {
        if (Objects.isNull(userUpdateEmailRequest) || Objects.isNull(request)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        Long userId = userUpdateEmailRequest.getUserId();
        String userEmail = userUpdateEmailRequest.getUserEmail();
        if (StringUtils.isBlank(userEmail) || Objects.isNull(userId)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能为空");
        // 分别找出「当前需要修改邮箱的用户」和「当前邮箱是 userEmail 的用户」
        LambdaQueryWrapper<User> wrapperAccount = new LambdaQueryWrapper<>();
        wrapperAccount.eq(User::getUserId, userId);
        User currentUser = userService.getOne(wrapperAccount);
        if (Objects.isNull(currentUser)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "当前用户不存在");
        LambdaQueryWrapper<User> wrapperEmail = new LambdaQueryWrapper<>();
        wrapperEmail.eq(User::getUserEmail, userEmail);
        User sameEmailUser = userService.getOne(wrapperEmail);
        if (!Objects.isNull(sameEmailUser) && !sameEmailUser.getUserId().equals(currentUser.getUserId()))
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户邮箱已存在!");
        userService.sendEmail(userEmail, currentUser.getUserAccount() + UserConstant.RESET_EMAIL_TOKEN);
        return ResultUtils.success(Boolean.TRUE);
    }

    /**
     * 给注册的用户发送验证码
     * @param userRegisterRequest 用户注册的 DTO 对象
     * @return 验证码是否发生成功
     */
    @PostMapping("/send/register/code")
    public BaseResponse<Boolean> userRegisterVerifyCode(@RequestBody UserRegisterRequest userRegisterRequest) {
        if (Objects.isNull(userRegisterRequest)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        String userEmail = userRegisterRequest.getUserEmail();
        if (StringUtils.isBlank(userEmail)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户邮箱不能为空");
        userService.sendEmail(userEmail, userEmail + UserConstant.REGISTER_EMAIL_TOKEN);
        return ResultUtils.success(Boolean.TRUE);
    }

    /**
     * 用户验证接口
     * @param userVerifyRequest 用户验证 DTO 对象
     * @return 用户验证响应 DTO 对象
     */
    @PostMapping("/verify")
    public BaseResponse<UserVerifyResponse> userVerify(@RequestBody UserVerifyRequest userVerifyRequest) {
        // 如果用户请求 or 输入的信息为空，那么就停止处理
        if (userVerifyRequest == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        String userAccount = userVerifyRequest.getUserAccount(), verificationCode = userVerifyRequest.getVerificationCode();
        if (StringUtils.isAnyBlank(userAccount, verificationCode)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        // 查看验证码是否正确
        userService.verifyEmailCode(userAccount + UserConstant.RESET_PASSWORD_TOKEN, verificationCode);
        UserVerifyResponse response = new UserVerifyResponse();
        response.setUserAccount(userAccount);
        return ResultUtils.success(response);
    }

    /**
     * 更新密码接口
     * @param resetPasswordRequest 用户重置密码 DTO 对象
     * @return 布尔值，表示是否成功更新密码
     */
    @PostMapping("/reset/password")
    public BaseResponse<Boolean> userResetPassword(@RequestBody UserRegisterRequest resetPasswordRequest) {
        // 如果用户请求 or 输入的信息为空，那么就停止处理
        if (resetPasswordRequest == null) throw new BusinessException(ErrorCode.REQUEST_ERROR, "请求对象为空");
        String userAccount = resetPasswordRequest.getUserAccount();
        String userPassword = resetPasswordRequest.getUserPassword(), verifyPassword = resetPasswordRequest.getVerifyPassword();
        if (StringUtils.isAnyBlank(userAccount, userPassword, verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        if (!userPassword.equals(verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次密码不一致!");
        // 用户重制密码
        userService.userResetPassword(userAccount, userPassword);
        return ResultUtils.success(Boolean.TRUE);
    }

    /**
     * 根据用户账户判断用户是否存在
     * @param registerRequest 用户注册 DTO 对象
     * @return 布尔值，判断是否存在
     */
    @PostMapping("/exists")
    public BaseResponse<Boolean> userExists(@RequestBody UserRegisterRequest registerRequest) {
        if (registerRequest == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求对象为空");
        boolean exists = userService.userExists(registerRequest);
        return exists ? ResultUtils.success(Boolean.TRUE) : ResultUtils.success(Boolean.FALSE);
    }
}