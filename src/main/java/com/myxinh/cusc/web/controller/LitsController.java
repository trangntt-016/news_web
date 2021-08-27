package com.myxinh.cusc.web.controller;

import com.myxinh.cusc.domain.Category;
import com.myxinh.cusc.domain.Lits;
import com.myxinh.cusc.repository.LitsRepository;
import com.myxinh.cusc.service.LitsService;
import com.myxinh.cusc.service.dto.ui.LitsDTO;
import com.myxinh.cusc.service.mapper.LitsConverter;
import com.myxinh.cusc.service.utils.SystemUtils;
import com.myxinh.cusc.web.constants.SystemConstants;
import com.myxinh.cusc.web.errors.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@CrossOrigin("http://localhost:4200")
public class LitsController {

    @Autowired
    private LitsRepository litsRepository;

    @Autowired
    private LitsService litsService;

    @GetMapping("/lits")//get List
    public ResponseEntity<List<Lits>> getAllLichTS(){
        return ResponseEntity.ok(litsRepository.findAll());
    }

    @GetMapping("/lits/{litsId}")//findOnebyId
    public ResponseEntity<Lits> getOneCategoryName(@PathVariable("litsId") int litsId){
        Optional<Lits> litsFind= litsService.findById(litsId);
        if(litsFind.isPresent()){
            return ResponseEntity.ok(litsFind.get());
        }else{
            throw new NotFoundException("Lits "+ ErrorConstants.NOT_FOUND);
        }
    }

    @PostMapping("/lits")//add new Lich_TS
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Lits> saveCategory(@RequestBody LitsDTO litsDTO) throws URISyntaxException, ParseException {
        if (litsDTO.getLits_id() != 0){
            throw new BadRequestAlertException(String.valueOf(litsDTO.getLits_id()));
        }else if (litsRepository.findOneByName(litsDTO.getLits_ten()).isPresent()){
            throw new IsAlreadyException(litsDTO.getLits_ten());
        }
        if (!SystemUtils.checkDateLogic(litsDTO.getLits_bddk(),litsDTO.getLits_ktdk())){
            throw new DateLogicException("Start Date and End Date");
        }
        else {
            Lits litsNew = litsService.addLits(litsDTO);
            return ResponseEntity.created(
                    new URI(SystemConstants.BASE_URL+"/lits/"+litsNew.getLits_id()))
                    .body(litsNew);
        }
    }

    @PutMapping("/lits")// update Lits existing in database
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Lits> updateCategory(@Valid @RequestBody LitsDTO litsDTO) throws URISyntaxException, ParseException {
        Optional<Lits> existingLits = litsRepository.findOneByName(litsDTO.getLits_ten());
        if (existingLits.isPresent() && !(existingLits.get().getLits_id() == litsDTO.getLits_id())){
            throw new IsAlreadyException(litsDTO.getLits_ten());
        }
       if (!SystemUtils.checkDateLogic(litsDTO.getLits_bddk(),litsDTO.getLits_ktdk())){
           throw new DateLogicException("Start Date and End Date");
       }
        Optional<Lits> newLits =litsService.updateLits(litsDTO);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/lits/"+litsDTO.getLits_id()));
        if (newLits.isPresent()){
            litsRepository.save(LitsConverter.convertToDomain(litsDTO));
            return ResponseEntity.ok(newLits.get());
        }else {
            return ResponseEntity.noContent().headers(headers).build();
        }
    }
//
    @DeleteMapping("/lits/{litsId}")//Delete Lits existing in database
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Void> deleteCategory(@PathVariable int litsId) throws URISyntaxException {
        litsService.deleteLits(litsId);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/lits/"+litsId));
        return ResponseEntity.noContent().headers(headers).build();
    }

}
