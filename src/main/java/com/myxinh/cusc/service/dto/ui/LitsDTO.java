package com.myxinh.cusc.service.dto.ui;

import com.myxinh.cusc.domain.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LitsDTO {

    private int lits_id;
    private String lits_ten;
    private boolean lits_thidauvao;
    private String lits_ngaythi;
    private String lits_ngaykg;
    private String lits_bddk;
    private String lits_ktdk;
    private String lits_tghoc;
    private String lits_ttkhac;
    private String link;
    private String username;
}
