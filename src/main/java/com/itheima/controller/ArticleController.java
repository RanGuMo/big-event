package com.itheima.controller;


import com.itheima.pojo.Article;
import com.itheima.pojo.Result;
import com.itheima.service.ArticleService;
import com.itheima.utils.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/article")
public class ArticleController {
    @Autowired
    private ArticleService articleService;

    @PostMapping
    public Result add(@RequestBody @Validated Article article) {
        articleService.add(article);
        return Result.success();
    }

    @GetMapping("/list")
    public Result<String> list(/*@RequestHeader(name = "Authorization") String token, HttpServletResponse response*/) {
       /* // 验证token
        try{
            Map<String, Object> claims = JwtUtil.parseToken(token);
            return Result.success("所有的文章数据。。。");
        }catch (Exception e){
            // http 响应状态码为401
            response.setStatus(401);
            return Result.error("未登录");
        }*/
        return Result.success("所有的文章数据。。。");
    }




}
