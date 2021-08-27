package com.myxinh.cusc.service;

import com.myxinh.cusc.domain.UserEntity;
import com.myxinh.cusc.repository.UserRepository;
import com.myxinh.cusc.security.UserNotActivatedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class DomainUserDetailsService implements UserDetailsService {

    @Autowired
    private final UserRepository userRepository;

    public DomainUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username)  {
        return userRepository.findOneWithAuthoritiesByUsername(username)
                .map(this::createSpringSecurityUser)
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " was not found in the database"));
    }

    private User createSpringSecurityUser(UserEntity userEntity) {
        if (!userEntity.isActive()) {
            throw new UserNotActivatedException("User " + userEntity.getUsername() + " was not activated");
        }
        List<GrantedAuthority> grantedAuthorities = userEntity.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getName()))
                .collect(Collectors.toList());
        return new User(userEntity.getUsername(),userEntity.getPassword(),grantedAuthorities);
    }


}
