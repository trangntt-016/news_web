package com.myxinh.cusc.service.dto.ui;

import com.myxinh.cusc.domain.Menu;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor  
public class MenuDTO implements Serializable {
    private int menuId;
    private String name;
    private List<Menu> submenu;
}
