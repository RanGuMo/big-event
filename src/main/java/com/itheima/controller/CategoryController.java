package com.itheima.controller;


import com.itheima.pojo.Category;
import com.itheima.pojo.Result;
import com.itheima.service.CategoryService;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/category")
public class CategoryController {

    // @Autowired
    // private CategoryService categoryService;
    private final CategoryService categoryService;

    @Autowired
    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    // 文章分类新增
    @PostMapping
    public Result<String> add(@RequestBody @Validated(Category.Add.class) Category category){
        categoryService.add(category);
        return Result.success();
    }

    // 文章分类列表
    @GetMapping
    public Result<List<Category>> list(){
        final List<Category> cs = categoryService.list();
        return Result.success(cs);
    }

    // 获取文章分类详情
    @GetMapping("/detail")
    public Result<Category> detail(@NotNull final Integer id){
        final Category c = categoryService.findById(id);
        return Result.success(c);
    }

    // 更新文章分类
    @PutMapping
    public Result<String> update(@RequestBody @Validated(Category.Update.class) Category category){
        categoryService.update(category);
        return Result.success();
    }

    // 删除文章分类
    @DeleteMapping
    public Result<String> delete(@NotNull final Integer id){
        categoryService.deleteById(id);
        return Result.success();
    }

}
