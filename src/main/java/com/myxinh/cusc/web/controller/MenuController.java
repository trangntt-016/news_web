package com.myxinh.cusc.web.controller;

import com.myxinh.cusc.domain.Category;
import com.myxinh.cusc.domain.Menu;
import com.myxinh.cusc.repository.MenuRepository;
import com.myxinh.cusc.service.MenuService;
import com.myxinh.cusc.service.dto.ui.MenuDTO;
import com.myxinh.cusc.web.constants.SystemConstants;
import com.myxinh.cusc.web.errors.BadRequestAlertException;
import com.myxinh.cusc.web.errors.IsAlreadyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;


@RestController
@RequestMapping("/api")
public class MenuController {

    @Autowired
    private MenuService menuService;

    @Autowired
    private MenuRepository menuRepository;

    @GetMapping("/menu")
    public ResponseEntity<List<MenuDTO>> getMenu(){
        return ResponseEntity.ok(menuService.getAll());
    }

    @PostMapping("/menu")//add new Menu
    public ResponseEntity<Menu> saveCategory(@RequestBody Menu menu) throws URISyntaxException {
        if (menu.getMenuId() != 0){
            throw new BadRequestAlertException(String.valueOf(menu.getMenuId()));
        }else if (menuRepository.findOneByMenuName(menu.getName()).isPresent()){
            throw new IsAlreadyException(menu.getName());
        }
        else {
            Menu newMenu = menuRepository.save(menu);
            return ResponseEntity.created(
                    new URI(SystemConstants.BASE_URL+"/categories/"+newMenu.getMenuId()))
                    .body(newMenu);
        }
    }

    @PutMapping("/menu")// update Menu existing in database
    public ResponseEntity<Menu> updateCategory(@Valid @RequestBody Menu menu) throws URISyntaxException {
        Optional<Menu> existingMenu = menuRepository.findOneByMenuName(menu.getName());
        if (existingMenu.isPresent() && !(existingMenu.get().getMenuId() == menu.getMenuId())){
            throw new IsAlreadyException(menu.getName());
        }
        Optional<Menu> newMenu =menuService.updateMenu(menu);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/categories/"+menu.getMenuId()));
        if (newMenu.isPresent()){
            menuRepository.save(menu);
            return ResponseEntity.ok(newMenu.get());
        }else {
            return ResponseEntity.noContent().headers(headers).build();
        }
    }

    @DeleteMapping("/categories/{menuId}")//Delete Menu existing in database
    public ResponseEntity<Void> deleteCategory(@PathVariable int menuId) throws URISyntaxException {
        menuService.deleteMenu(menuId);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(SystemConstants.BASE_URL+"/categories/"+menuId));
        return ResponseEntity.noContent().headers(headers).build();
    }
}
