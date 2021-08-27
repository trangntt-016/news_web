package com.myxinh.cusc.web.controller;

import com.myxinh.cusc.domain.Role;
import com.myxinh.cusc.service.UserService;
import com.myxinh.cusc.service.dto.UserDTO;
import com.myxinh.cusc.web.errors.NotFoundException;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserDTO> getAll(){
        return userService.getAllUser();
    }

    @GetMapping("/account")
    public UserDTO getAccount() {
        return userService.getUserWithAuthorities()
                .map(userEntity -> new UserDTO(userEntity.getUsername()
                        ,userEntity.getFullName()
                        ,userEntity.isActive()
                        ,userEntity.getRoles().stream().map(Role::getName).collect(Collectors.toList())
                ))
                .orElseThrow(() -> new NotFoundException("User could not be found"));
    }
    @GetMapping("/authenticate")
    public String isAuthenticated(HttpServletRequest request) {
        return request.getRemoteUser();
    }


}
