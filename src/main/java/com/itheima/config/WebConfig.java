package com.itheima.config;

import com.itheima.interceptors.LoginInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private static final List<String> BYPASS_PATHS = List.of(
            "/user/login",
            "/user/register");

    @Autowired
    private LoginInterceptor loginInterceptor;

    // 添加拦截器
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
       // 登录接口和注册接口不拦截
       //  registry.addInterceptor(loginInterceptor).excludePathPatterns("/user/login","/user/register");
        registry.addInterceptor(loginInterceptor).excludePathPatterns(BYPASS_PATHS);
    }
}
