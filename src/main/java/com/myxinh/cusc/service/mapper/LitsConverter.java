package com.myxinh.cusc.service.mapper;

import com.myxinh.cusc.domain.Lits;
import com.myxinh.cusc.service.dto.ui.LitsDTO;
import com.myxinh.cusc.service.utils.SystemUtils;
import org.springframework.stereotype.Service;

@Service
public class LitsConverter {

    public static Lits convertToDomain(LitsDTO litsDTO){
        Lits newLits = new Lits();
        newLits.setLits_id(litsDTO.getLits_id());
        newLits.setLits_ten(litsDTO.getLits_ten());
        newLits.setLits_thidauvao(litsDTO.isLits_thidauvao());
        newLits.setLits_ngaythi(SystemUtils.getDate(litsDTO.getLits_ngaythi()));
        newLits.setLits_ngaykg(SystemUtils.getDate(litsDTO.getLits_ngaykg()));
        newLits.setLits_bddk(SystemUtils.getDate(litsDTO.getLits_bddk()));
        newLits.setLits_ktdk(SystemUtils.getDate(litsDTO.getLits_ktdk()));
        newLits.setLits_tghoc(litsDTO.getLits_tghoc());
        newLits.setLits_ttkhac(litsDTO.getLits_ttkhac());
        newLits.setLink(litsDTO.getLink());
        return newLits;
    }
    public static LitsDTO covertToViews(Lits lits){
        LitsDTO litsDTO = new LitsDTO();
        litsDTO.setLits_id(lits.getLits_id());
        litsDTO.setLits_ten(litsDTO.getLits_ten());
        litsDTO.setLits_thidauvao(litsDTO.isLits_thidauvao());
        litsDTO.setLits_ngaythi(litsDTO.getLits_ngaythi());
        litsDTO.setLits_ngaykg(litsDTO.getLits_ngaykg());
        litsDTO.setLits_bddk(litsDTO.getLits_bddk());
        litsDTO.setLits_ktdk(litsDTO.getLits_ktdk());
        litsDTO.setLits_tghoc(litsDTO.getLits_tghoc());
        litsDTO.setLits_ttkhac(litsDTO.getLits_ttkhac());
        litsDTO.setLink(litsDTO.getLink());
        litsDTO.setUsername(lits.getUser().getUsername());
        return litsDTO;
    }
}
