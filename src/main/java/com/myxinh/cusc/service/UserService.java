package com.myxinh.cusc.service;

import com.myxinh.cusc.domain.Role;
import com.myxinh.cusc.domain.UserEntity;
import com.myxinh.cusc.repository.UserRepository;
import com.myxinh.cusc.security.SecurityUtils;
import com.myxinh.cusc.service.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService{

    @Autowired
    UserRepository userRepository;

    public List<UserDTO> getAllUser(){
        return userRepository.findAll()
                .stream()
                .map(userEntity -> new UserDTO(
                        userEntity.getUsername(),userEntity.getFullName(),
                        userEntity.isActive(),
                        userEntity
                                .getRoles()
                                .stream()
                                .map(Role::getName)
                                .collect(Collectors.toList())))
                .collect(Collectors.toList());
    }

    public Optional<UserDTO> getUserByUsername(String username) {
        return Optional.of(userRepository
                .findUserEntityByUsername(username))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .map(userEntity -> new UserDTO(
                        userEntity.getUsername(),
                        userEntity.getFullName(),
                        userEntity.isActive(),
                        userEntity.getRoles().stream().map(Role::getName).collect(Collectors.toList())));
    }

    public Optional<UserEntity> getUserWithAuthorities() {
        return SecurityUtils.getCurrentUserLogin().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
