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
import com.project.ethansystem.utils.EmailUtils;
import com.project.ethansystem.utils.ResultUtils;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 用户响应处理器
 * @author Ethan
 */

@RestController
@Slf4j
@RequestMapping("/user")
public class UserController {
    @Resource
    private UserService userService;

    @Resource
    private EmailUtils emailUtils;

    // 验证码缓存
    private final Map<String, String> verificationCodeCache = new HashMap<>();

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
        String inviteCode = userRegisterRequest.getInviteCode();
        if (StringUtils.isAnyBlank(userAccount, userPassword, userEmail, verifyPassword, inviteCode)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数不能为空");
        Long userId = userService.userRegister(userAccount, userPassword, verifyPassword, userEmail, inviteCode);
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
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.like(StringUtils.isNotBlank(username), User::getUsername, username);
        queryWrapper.eq(userId != null, User::getUserId, userId);
        User targetUser = userService.getOne(queryWrapper);
        // 返回脱敏后的用户数据
        User safetyUser = userService.getSafetyUser(targetUser);
        return ResultUtils.success(safetyUser);
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
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(userId != null, User::getUserId, userId);
        queryWrapper.like(StringUtils.isNotBlank(username), User::getUsername, username);
        queryWrapper.eq(userSex != null, User::getUserSex, userSex);
        queryWrapper.eq(userEmail != null, User::getUserEmail, userEmail);
        queryWrapper.eq(userRole != null, User::getUserRole, userRole);
        queryWrapper.eq(userStatus != null, User::getUserStatus, userStatus);
        List<User> targetUsers = userService.getBaseMapper().selectList(queryWrapper);
        // 返回脱敏后的用户数据
        List<User> safetyUsers = targetUsers.stream().map((currentUser) -> userService.getSafetyUser(currentUser)).toList();
        return ResultUtils.success(safetyUsers);
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
        List<User> userLists = userService.list();
        // 返回脱敏后的用户数据
        userLists = userLists.stream().map(currentUser -> userService.getSafetyUser(currentUser)).toList();
        return ResultUtils.success(userLists);
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
    public BaseResponse<User> UserUpdate(@RequestBody User user, HttpServletRequest request) {
        if (user == null || request == null) throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户对象为空");
        User safetyUser = userService.userUpdate(user, request);
        return ResultUtils.success(safetyUser);
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
        if (currentUser.getUserEmail() == null) throw new BusinessException(ErrorCode.NULL_ERROR, "用户没有设置邮箱，请联系管理员设置密码");
        // 如果用户状态异常，也无法重置密码
        if (currentUser.getUserStatus().equals(UserConstant.USER_ABNORMAL)) throw new BusinessException(ErrorCode.NULL_ERROR, "用户状态异常，请联系管理员");
        String email = currentUser.getUserEmail(), verificationCode = UUID.randomUUID().toString();
        try {
            emailUtils.sendMail(email, verificationCode);
            verificationCodeCache.put(userAccount, verificationCode);       // 把验证码放入到缓存中，这样后面可以验证用户
        }
        catch (Exception exception) {
            log.error("消息发送失败，原因如下: " + exception.getMessage());
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, exception.getMessage());
        }
        UserVerifyResponse response = new UserVerifyResponse();
        response.setUserAccount(userAccount);
        return ResultUtils.success(response);
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
        // 如果验证码输入错误，就直接报错
        String verificationCodeFromCache = verificationCodeCache.getOrDefault(userAccount, null);
        if (!verificationCode.equals(verificationCodeFromCache)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "验证码输入错误，请重新输入");
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
        // 构造修改密码后的新对象和条件对象
        String safetyPassword = DigestUtils.md5DigestAsHex((UserConstant.SALT + userPassword).getBytes());
        User user = new User();
        user.setUserPassword(safetyPassword);
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        boolean status = userService.update(user, queryWrapper);
        if (!status) throw new BusinessException(ErrorCode.SYSTEM_ERROR, "密码更新失败，请重试");
        // 如果更新成功，那么把验证码从缓存中删除，避免二次使用
        verificationCodeCache.remove(userAccount);
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
        String userAccount = registerRequest.getUserAccount();
        String userPassword = registerRequest.getUserPassword();
        String verifyPassword = registerRequest.getVerifyPassword();
        if (StringUtils.isAnyBlank(userAccount, userPassword, verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数非法");
        if (!userPassword.equals(verifyPassword)) throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次密码输入不一致");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserAccount, userAccount);
        User user = userService.getOne(queryWrapper);
        return user == null ? ResultUtils.success(Boolean.FALSE) : ResultUtils.success(Boolean.TRUE);
    }
}