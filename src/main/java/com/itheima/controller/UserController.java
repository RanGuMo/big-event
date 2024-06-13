package com.itheima.controller;

import com.itheima.pojo.Result;
import com.itheima.pojo.User;
import com.itheima.service.UserService;
import com.itheima.utils.JwtUtil;
import com.itheima.utils.Md5Util;
import com.itheima.utils.ThreadLocalUtil;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.URL;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/user")
@Validated
public class UserController {
    // @Autowired
    // private UserService userService;
    //
    // @Autowired
    // private StringRedisTemplate stringRedisTemplate;

    private final UserService userService;
    private final StringRedisTemplate stringRedisTemplate;

    @Autowired
    public UserController(UserService userService, StringRedisTemplate stringRedisTemplate) {
        this.userService = userService;
        this.stringRedisTemplate = stringRedisTemplate;
    }

    /**
     * 注册
     * @param username
     * @param password
     * @return
     */
    @PostMapping("/register")
    public Result<String> register(@Pattern(regexp = "^\\S{5,16}$")final String username, @Pattern(regexp = "^\\S{5,16}$")final String password){
        //查询用户
        final  User u = userService.findByUserName(username);
        if (u == null) {
            //没有占用
            //注册
            userService.register(username, password);
            return Result.success();
        } else {
            //占用
            return Result.error("用户名已被占用");
        }
    }

    /**
     * 登录
     * @param username
     * @param password
     * @return
     */
    @PostMapping("/login")
    public Result<String> login(@Pattern(regexp = "^\\S{5,16}$")final String username, @Pattern(regexp = "^\\S{5,16}$")final String password) {
        //根据用户名查询用户
        final User loginUser = userService.findByUserName(username);
        //判断该用户是否存在
        if (loginUser == null) {
            return Result.error("用户名错误");
        }

        //判断密码是否正确  loginUser对象中的password是密文
        if (Md5Util.getMD5String(password).equals(loginUser.getPassword())) {
            //登录成功
            final Map<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            final String token = JwtUtil.genToken(claims);

            //把token存储到redis中
            final ValueOperations<String, String> operations = stringRedisTemplate.opsForValue();
            operations.set(token,token,1, TimeUnit.HOURS);  // 1小时后自动从redis中删除

            return Result.success(token);
            // return Result.success("jwt 令牌。。。");
        }
        return Result.error("密码错误");
    }

    /**
     * 获取用户详细信息
     * @param token 请求头Authorization 携带的token
     * @return 用户详细信息
     */
    @GetMapping("/userInfo")
    public Result<User> userInfo(/*@RequestHeader(name = "Authorization") String token*/){
        /*// 根据用户名查询用户
        final Map<String, Object> map = JwtUtil.parseToken(token);
        final String username = (String) map.get("username");*/

        final Map<String, Object> map = ThreadLocalUtil.get();
        final String username = (String) map.get("username");

        final User user = userService.findByUserName(username);
        return Result.success(user);
    }

    /**
     * 更新用户基本信息
     * @param user
     * @return
     */
    @PutMapping("/update")
    public Result<String> update(@RequestBody @Validated final User user){
        final Map<String,Object> map = ThreadLocalUtil.get();
        final  Integer id = (Integer) map.get("id");
        if(user.getId().equals(id)){
            userService.update(user);
            return Result.success();
        }else {
            return Result.error("非本人id");
        }

    }

    /**
     * 更新用户头像
     * @param avatarUrl 参数为URL地址值
     * @return
     */
    // @PatchMapping("/updateAvatar")
    // public Result<String> updateAvatar(@RequestParam @URL final String avatarUrl) {
    //     userService.updateAvatar(avatarUrl);
    //     return Result.success();
    // }
    @PatchMapping("/updateAvatar")
    public Result<String> updateAvatar(@RequestParam final String avatarUrl) {
        userService.updateAvatar(avatarUrl);
        return Result.success();
    }


    /**
     * 更新用户密码
     * @param params
     * @return
     */
    @PatchMapping("/updatePwd")
    public Result<String> updatePwd(@RequestBody Map<String, String> params,@RequestHeader("Authorization")final String token) {
        //1.校验参数
        final String oldPwd = params.get("old_pwd");
        final String newPwd = params.get("new_pwd");
        final String rePwd = params.get("re_pwd");

        if (!StringUtils.hasLength(oldPwd) || !StringUtils.hasLength(newPwd) || !StringUtils.hasLength(rePwd)) {
            return Result.error("缺少必要的参数");
        }

        //原密码是否正确
        //调用userService根据用户名拿到原密码,再和old_pwd比对
        final Map<String,Object> map = ThreadLocalUtil.get();
        final String username = (String) map.get("username");
        final User loginUser = userService.findByUserName(username);
        if (!loginUser.getPassword().equals(Md5Util.getMD5String(oldPwd))){
            return Result.error("原密码填写不正确");
        }

        //newPwd和rePwd是否一样
        if (!rePwd.equals(newPwd)){
            return Result.error("两次填写的新密码不一样");
        }

        //2.调用service完成密码更新
        userService.updatePwd(newPwd);
        //删除redis中对应的token
        final ValueOperations<String, String> operations = stringRedisTemplate.opsForValue();
        operations.getOperations().delete(token);

        return Result.success();
    }
}
