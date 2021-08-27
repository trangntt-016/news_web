package com.myxinh.cusc.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "news")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class News implements Serializable {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "news_id")
    private int newsId;

    @Column(name = "title",length = 50,nullable = false)
    private String title;

    @Column(name = "short_content",length = 500,nullable = false)
    private String shortContent;

    @Column(name = "detail", nullable = false)
    private String detail;

    @Column(name = "image_path",nullable = false,length = 60)
    private String imagePath;

    @Column(name = "created_date")
    private Date createdDate;

    @Column(name = "main_news")
    private boolean mainNews;

    @Column(name = "status")
    private boolean status;

    @ManyToOne(cascade = CascadeType.MERGE,fetch = FetchType.LAZY)
    @JoinColumn(name = "menu_id")
    private Menu menu;

    @ManyToOne(cascade = CascadeType.MERGE)
    @JoinColumn(name = "category_id")
    private Category category;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "user_id")
    private UserEntity user;

}
