package com.itheima.service;

import com.itheima.pojo.Article;
import com.itheima.pojo.PageBean;

public interface ArticleService {

    // 发布文章（新增）
    void add(Article article);

    // 文章列表（分页查询）
    PageBean<Article> list(Integer pageNum, Integer pageSize, Integer categoryId, String state);

    // 通过Id 获取文章详情
    Article findById(Integer id);

    // 更新文章
    void update(Article article);
}
