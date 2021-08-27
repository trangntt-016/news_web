package com.myxinh.cusc.service;

import com.myxinh.cusc.domain.Category;
import com.myxinh.cusc.domain.Lits;
import com.myxinh.cusc.repository.LitsRepository;
import com.myxinh.cusc.repository.UserRepository;
import com.myxinh.cusc.service.dto.ui.LitsDTO;
import com.myxinh.cusc.service.mapper.LitsConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class LitsService {

    @Autowired
    private LitsRepository litsRepository;

    @Autowired
    private UserRepository userRepository;

    public Lits addLits(LitsDTO litsDTO){
        Lits litsAdd = LitsConverter.convertToDomain(litsDTO);
        userRepository.findUserEntityByUsername(litsDTO.getUsername()).ifPresent(litsAdd::setUser);
        return litsRepository.save(litsAdd);
    }

    public Optional<Lits> updateLits(LitsDTO litsDTO){
        return Optional.of(litsRepository
                .findById(litsDTO.getLits_id()))
                .filter(Optional::isPresent)
                .map(Optional::get);
    }

    public void deleteLits(int litsId){
        litsRepository.findById(litsId).ifPresent(
                lits -> {litsRepository.delete(lits);}
        );
    }
    public Optional<Lits> findById(int litsId){
        return litsRepository.findById(litsId);
    }

}
