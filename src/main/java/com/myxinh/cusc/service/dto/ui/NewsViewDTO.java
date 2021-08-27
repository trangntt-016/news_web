package com.myxinh.cusc.service.dto.ui;

import com.myxinh.cusc.domain.Category;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class NewsViewDTO {
    private int newsId;
    private String title;
    private String shortContent;
    private String imagePath;
    private String categoryName;
    private boolean mainNews;
    private boolean status;
}
