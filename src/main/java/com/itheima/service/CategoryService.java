package com.itheima.service;

import com.itheima.pojo.Category;

import java.util.List;

public interface CategoryService {
    //新增分类
    void add(Category category);

    // 分类列表
    List<Category> list();

    // 分类详情
    Category findById(Integer id);

    // 更新文章分类
    void update(Category category);
}
