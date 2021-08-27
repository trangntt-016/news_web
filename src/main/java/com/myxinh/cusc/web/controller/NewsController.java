package com.myxinh.cusc.web.controller;

import com.myxinh.cusc.domain.News;
import com.myxinh.cusc.repository.NewsRepository;
import com.myxinh.cusc.service.NewsService;
import com.myxinh.cusc.service.dto.ui.NewsUploadDTO;
import com.myxinh.cusc.service.dto.ui.NewsViewDTO;
import com.myxinh.cusc.web.constants.SystemConstants;
import com.myxinh.cusc.web.errors.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class NewsController {

    @Autowired
    private NewsService newsService;

    @Autowired
    private NewsRepository newsRepository;

    @GetMapping("/news/view")// Get View of News
    public ResponseEntity<List<NewsViewDTO>> getAllNewsByTitle(){
        return ResponseEntity.ok(newsService.getAllNewsView());
    }

    @GetMapping("/news/{newsId}")// Get News Detail
    public ResponseEntity<News> getNewsById(@PathVariable("newsId") int newsId) throws IOException {
        Optional<News> newsFind = newsService.findById(newsId);
        if (newsFind.isPresent()){
            return ResponseEntity.ok(newsFind.get());
        }else {
            throw new NotFoundException("News "+ ErrorConstants.NOT_FOUND);
        }
    }

    @PreAuthorize("hasAnyRole('WRITER','ADMIN')")
    @GetMapping("/news/type") ResponseEntity<List<NewsViewDTO>> findAllByCondition(
            @RequestParam(value = "categoryId",defaultValue = "") String categoryId,
            @RequestParam(value = "menuId",defaultValue = "0") String menuId){
        int categoryIdInput = 0;
        int menuIdInput =0;
        if (!categoryId.equals("")){
            categoryIdInput = Integer.parseInt(categoryId);
        }
        else if (!menuId.equals("")){
            menuIdInput = Integer.parseInt((menuId));
        }
        return ResponseEntity.ok(newsService.getNewsByCategoryIdOrMenuId(categoryIdInput,menuIdInput));
    }

    @PostMapping("/news")//Add new News
    @PreAuthorize("hasAnyRole('WRITER','ADMIN')")
    public ResponseEntity<News> saveCategory(@ModelAttribute NewsUploadDTO newsUploadDTO) throws URISyntaxException {
        if (!newsUploadDTO.getNewsId().equals("")) {
            throw new BadRequestAlertException(newsUploadDTO.getNewsId());
        }
        if (newsService.isMainNews(Integer.parseInt(newsUploadDTO.getCategoryId())).isPresent() &&
            newsUploadDTO.getMainNews().equals("true") ){
            throw new ExistMainNewsException(ErrorConstants.EXIST_MAIN_NEWS);
        }
        if (Integer.parseInt(newsUploadDTO.getCategoryId()) == 0 &&
            Integer.parseInt(newsUploadDTO.getMenuId()) == 0){
            throw new NullException("Category and Menu");
        }
        else {
            News newNews = newsService.addNews(newsUploadDTO);
            return ResponseEntity.created(
                    new URI(SystemConstants.BASE_URL+"/news/"+newsUploadDTO.getNewsId()))
                    .body(newNews);
        }
    }

    @PutMapping("/news")//Update News existing in database
    @PreAuthorize("hasAnyRole('WRITER','ADMIN')")
    public ResponseEntity<News> updateCategory(@ModelAttribute NewsUploadDTO newsUploadDTO) throws URISyntaxException {
        if (newsUploadDTO.getNewsId().equals("")) {
            throw new BadRequestAlertException(newsUploadDTO.getNewsId());
        }
        if (newsService.isMainNews(Integer.parseInt(newsUploadDTO.getCategoryId())).isPresent()){
            throw new ExistMainNewsException(ErrorConstants.EXIST_MAIN_NEWS);
        }
        Optional<News> newsUpdate = newsService.updateNews(newsUploadDTO);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/news/"+newsUploadDTO.getNewsId()));
        if (newsUpdate.isEmpty()){
            return ResponseEntity.noContent().headers(headers).build();
        }else {
            return ResponseEntity.ok(newsUpdate.get());
        }
    }

    @DeleteMapping("/news/{newsId}")//Delete Category existing in database
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteCategory(@PathVariable ("newsId") int newsId) throws URISyntaxException {
        newsService.deleteNews(newsId);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/news/"+newsId));
        return ResponseEntity.noContent().headers(headers).build();
    }

    @PutMapping("/news/{newsId}") //Update news status:localhost:3000/api/news/13/?status=true
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> updateNewsStatus(
            @PathVariable("newsId")  int newsId,
            @RequestParam("status") String status
    ) throws URISyntaxException {
        newsService.updateNewsStatus(newsId,Boolean.parseBoolean(status));
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/news/"+newsId+"status?"+status));
        return ResponseEntity.noContent().headers(headers).build();
    }

}
