package com.itheima.service;

import com.itheima.pojo.User;

public interface UserService {
    //根据用户名查询用户
    User findByUserName(String username);

    //注册(新增数据)
    void register(String username, String password);

    // 更新用户信息
    void update(User user);
}
