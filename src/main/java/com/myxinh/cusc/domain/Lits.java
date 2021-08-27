package com.myxinh.cusc.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "lits")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Lits implements Serializable {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "lits_id")
    private int lits_id;

    @Column(name = "lits_ten",nullable = false)
    private String lits_ten;

    @Column(name = "lits_thidauvao",nullable = false)
    private boolean lits_thidauvao;

    @Column(name = "lits_ngaythi")
    private String lits_ngaythi;

    @Column(name = "lits_ngaykg",nullable = false)
    private String lits_ngaykg;

    @Column(name = "lits_bddk",nullable = false)
    private String lits_bddk;

    @Column(name = "lits_ktdk",nullable = false)
    private String lits_ktdk;

    @Column(name = "lits_tghoc",nullable = false)
    private String lits_tghoc;

    @Column(name = "lits_ttkhac")
    private String lits_ttkhac;

    @Column(name = "link")
    private String link;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id",updatable = false)
    @JsonIgnore
    private UserEntity user;

}
