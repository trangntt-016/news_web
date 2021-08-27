package com.myxinh.cusc.repository;

import com.myxinh.cusc.domain.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface CategoryRepository extends JpaRepository<Category,Integer> {

    @Query("SELECT c FROM Category c WHERE c.categoryName = :categoryName")
    Optional<Category> findOneByCategoryName(@Param("categoryName") String categoryName);

    @Query("SELECT c.categoryName FROM Category c WHERE c.categoryId=:categoryId")
    Optional<Category> findOneByCategoryId(@Param("categoryId") int categoryId);
}

