package com.myxinh.cusc.repository;

import com.myxinh.cusc.domain.News;
import com.myxinh.cusc.service.dto.ui.NewsViewDTO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;


public interface NewsRepository extends JpaRepository<News, Integer> {

    @Query("SELECT NEW com.myxinh.cusc.service.dto.ui.NewsViewDTO(" +
            "n.newsId,n.title,n.shortContent,n.imagePath,n.category.categoryName,n.mainNews,n.status)" +
            " FROM News n")
    List<NewsViewDTO> findAllNewsView();

    @Query("SELECT NEW com.myxinh.cusc.service.dto.ui.NewsViewDTO(" +
            "n.newsId,n.title,n.shortContent,n.imagePath,n.category.categoryName,n.mainNews,n.status)" +
            "FROM News n WHERE n.category.categoryId =:categoryId OR n.menu.menuId =:menuId")
    List<NewsViewDTO> findNewsByCategoryIdOrMenuId(@Param("categoryId") int categoryId,@Param("menuId") int menuId);

    @Modifying
    @Transactional
    @Query("UPDATE News n SET n.status =:status  WHERE n.newsId =:newsId")
    void updateNewStatus(@Param("status") boolean status,@Param("newsId")int newsId);

    @Query("SELECT n FROM News n WHERE n.mainNews = true AND n.category.categoryId =:categoryId")
    Optional<News> isMainNews(@Param("categoryId") int categoryId);

}


