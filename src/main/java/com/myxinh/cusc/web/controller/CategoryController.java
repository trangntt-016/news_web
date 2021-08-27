package com.myxinh.cusc.web.controller;

import com.myxinh.cusc.domain.Category;
import com.myxinh.cusc.repository.CategoryRepository;
import com.myxinh.cusc.service.CategoryService;
import com.myxinh.cusc.web.constants.SystemConstants;
import com.myxinh.cusc.web.errors.BadRequestAlertException;
import com.myxinh.cusc.web.errors.ErrorConstants;
import com.myxinh.cusc.web.errors.IsAlreadyException;
import com.myxinh.cusc.web.errors.NotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private CategoryRepository categoryRepository;

    @GetMapping("/categories")//get List
    public ResponseEntity<List<Category>> getAllCategory(){
        return ResponseEntity.ok(categoryRepository.findAll());
    }

    @GetMapping("/categories/{categoryId}")//get oneNameByCategoryId
    public ResponseEntity<Category> getOneCategoryName(@PathVariable("categoryId") int categoryId){
        Optional<Category> categoryFind= categoryService.findById(categoryId);
        if(categoryFind.isPresent()){
            return  ResponseEntity.ok(categoryFind.get());
        }else{
            throw new NotFoundException("Category "+ ErrorConstants.NOT_FOUND);
        }
    }
    @PostMapping("/categories")//add new Category
    public ResponseEntity<Category> saveCategory(@RequestBody Category category) throws URISyntaxException {
        if (category.getCategoryId() != 0){
            throw new BadRequestAlertException(String.valueOf(category.getCategoryId()));
        }else if (categoryRepository.findOneByCategoryName(category.getCategoryName()).isPresent()){
            throw new IsAlreadyException(category.getCategoryName());
        }
        else {
            Category newCategory = categoryRepository.save(category);
            return ResponseEntity.created(
                    new URI(SystemConstants.BASE_URL+"/categories/"+newCategory.getCategoryId()))
                    .body(newCategory);
        }
    }

    @PutMapping("/categories")// update Category existing in database
    public ResponseEntity<Category> updateCategory(@Valid @RequestBody Category category) throws URISyntaxException {
        Optional<Category> existingCategory = categoryRepository.findOneByCategoryName(category.getCategoryName());
        if (existingCategory.isPresent() && !(existingCategory.get().getCategoryId() == category.getCategoryId())){
            throw new IsAlreadyException(category.getCategoryName());
        }
        Optional<Category> newCategory =categoryService.updateCategory(category);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/categories/"+category.getCategoryId()));
        if (newCategory.isPresent()){
            categoryRepository.save(category);
            return ResponseEntity.ok(newCategory.get());
        }else {
            return ResponseEntity.noContent().headers(headers).build();
        }
    }

    @DeleteMapping("/categories/{categoryId}")//Delete Category existing in database
    public ResponseEntity<Void> deleteCategory(@PathVariable int categoryId) throws URISyntaxException {
        categoryService.deleteCategory(categoryId);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/categories/"+categoryId));
        return ResponseEntity.noContent().headers(headers).build();
    }
}
