package com.myxinh.cusc;

import com.myxinh.cusc.service.MenuService;
import com.myxinh.cusc.service.dto.ui.MenuDTO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@SpringBootTest
class CuscApplicationTests {
    @Autowired
    MenuService menuService;

    @Test
    void getallMenu() {
        List<MenuDTO> menuDTOList = new ArrayList<>();
        menuDTOList = menuService.getAll();
        String a = "11";

    }

}
