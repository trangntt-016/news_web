package com.myxinh.cusc.service;

import com.myxinh.cusc.domain.Category;
import com.myxinh.cusc.domain.Menu;
import com.myxinh.cusc.repository.MenuRepository;
import com.myxinh.cusc.service.dto.ui.MenuDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class MenuService {

    @Autowired
    private MenuRepository menuRepository;

    public List<MenuDTO> getAll() {
        List<Menu> menus = menuRepository.findAll();
        return menus.stream()
                .filter(menu -> menu.getParentId() == 0)
                .map(menu -> getMenuWithSub(menu,menus))
                .collect(Collectors.toList());
    }

    public MenuDTO getMenuWithSub(Menu menu,List<Menu> menus) {
        List<Menu> listSub = new ArrayList<>();
        MenuDTO menuDTO = new MenuDTO();
        menuDTO.setMenuId(menu.getMenuId());
        menuDTO.setName(menu.getName());
        for (Menu submenu : menus) {
             if (submenu.getParentId() == menu.getMenuId()) {
                 listSub.add(submenu);
             }
        }
        menuDTO.setSubmenu(listSub);
        return menuDTO;
    }

    public Optional<Menu> updateMenu(Menu menu){
        return Optional.of(menuRepository
                .findById(menu.getMenuId()))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .map(oldMenu -> new Menu(menu.getMenuId(),menu.getName(),menu.getParentId()));
    }

    public void deleteMenu(int menuId){
        menuRepository.findById(menuId).ifPresent(
                menu -> {menuRepository.delete(menu);}
        );
    }
}
