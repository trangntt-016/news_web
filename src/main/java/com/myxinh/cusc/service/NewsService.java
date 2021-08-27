package com.myxinh.cusc.service;

import com.myxinh.cusc.domain.Category;
import com.myxinh.cusc.domain.News;
import com.myxinh.cusc.repository.MenuRepository;
import com.myxinh.cusc.repository.NewsRepository;
import com.myxinh.cusc.repository.UserRepository;
import com.myxinh.cusc.service.dto.ui.NewsUploadDTO;
import com.myxinh.cusc.service.dto.ui.NewsViewDTO;
import com.myxinh.cusc.web.constants.SystemConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.io.*;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

@Service
public class NewsService{
    @Autowired
    private NewsRepository newsRepository;

    @Autowired
    private MenuRepository menuRepository;

    @Autowired
    private UserRepository userRepository;

    public News addNews(NewsUploadDTO newsUploadDTO){
        try {
            File file = new File(SystemConstants.IMAGE_DIRECTORY + newsUploadDTO.getImagePath().getOriginalFilename());//;lưu ảnh vào folder dự án
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(newsUploadDTO.getImagePath().getBytes());
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        News news = new News();
        news.setNewsId(0);
        news.setTitle(newsUploadDTO.getTitle());
        news.setShortContent(newsUploadDTO.getShortContent());
        news.setDetail(newsUploadDTO.getDetail());
        news.setImagePath(newsUploadDTO.getImagePath().getOriginalFilename().trim());
        news.setCreatedDate(timestamp);
        news.setMainNews(Boolean.parseBoolean(newsUploadDTO.getMainNews()));
        userRepository.findUserEntityByUsername(newsUploadDTO.getUsername()).ifPresent(
                news::setUser
        );
        if (Integer.parseInt(newsUploadDTO.getCategoryId()) != 0){
            news.setCategory(new Category(Integer.parseInt(newsUploadDTO.getCategoryId()),""));
        }else {
            news.setCategory(null);
        }
        if (Integer.parseInt(newsUploadDTO.getMenuId()) != 0){
            news.setMenu(
                    Optional.of(menuRepository.findById(Integer.parseInt(newsUploadDTO.getMenuId())))
                            .filter(Optional::isPresent)
                            .map(Optional::get)
                            .orElse(null)
            );
        }else {
            news.setMenu(null);
        }
        return newsRepository.save(news);
    }

    public List<NewsViewDTO> getAllNewsView(){
        return newsRepository.findAllNewsView();
    }

    public Optional<News> findById(int id) throws IOException {
        return newsRepository.findById(id);
    }

    public List<NewsViewDTO> getNewsByCategoryIdOrMenuId(int categoryId,int menuId){
        return newsRepository.findNewsByCategoryIdOrMenuId(categoryId,menuId);
    }

    public Optional<News> updateNews(NewsUploadDTO newsUploadDTO){
        Optional<News> newsFind = newsRepository.findById(Integer.parseInt(newsUploadDTO.getNewsId()));
        if (newsFind.isPresent()){
            News news = newsFind.get();
            String imageName = newsUploadDTO.getImagePath().getOriginalFilename();
            if (imageName != null && !imageName.equals(news.getImagePath())) {
                try {
                    File file = new File(SystemConstants.IMAGE_DIRECTORY + newsUploadDTO.getImagePath().getOriginalFilename());//;lưu ảnh vào folder dự án
                    FileOutputStream fileOutputStream = new FileOutputStream(file);
                    fileOutputStream.write(newsUploadDTO.getImagePath().getBytes());
                    news.setImagePath(newsUploadDTO.getImagePath().getOriginalFilename().trim());
                    fileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            news.setNewsId(Integer.parseInt(newsUploadDTO.getNewsId()));
            news.setTitle(newsUploadDTO.getTitle());
            news.setShortContent(newsUploadDTO.getShortContent());
            news.setDetail(newsUploadDTO.getDetail());
            news.setMainNews(Boolean.parseBoolean(newsUploadDTO.getMainNews()));
            news.setCategory(new Category(Integer.parseInt(newsUploadDTO.getCategoryId()),""));
            news.setMenu(
                    Optional.of(menuRepository.findById(Integer.parseInt(newsUploadDTO.getMenuId())))
                            .filter(Optional::isPresent)
                            .map(Optional::get)
                            .orElse(null)
            );
            return Optional.of(newsRepository.save(news));
        }
        return Optional.empty();
    }

    public void deleteNews(int newsId){
        newsRepository.findById(newsId).ifPresent(
                news -> {newsRepository.delete(news);}
        );
    }

    public void updateNewsStatus(int newsId,boolean status){

        newsRepository.findById(newsId).ifPresent(
                news -> {newsRepository.updateNewStatus(status,newsId);}
        );
    }

    public Optional<News> isMainNews(int categoryId){
        return newsRepository.isMainNews(categoryId);
    }

}
