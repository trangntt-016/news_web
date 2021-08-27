package com.myxinh.cusc.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import com.myxinh.cusc.domain.UserEntity;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity,String>{

    @EntityGraph(attributePaths = "roles")
    Optional<UserEntity> findOneWithAuthoritiesByUsername(String userName);

    @Query("SELECT u FROM UserEntity u WHERE u.username =:username")
    Optional<UserEntity> findUserEntityByUsername(@Param("username") String username);
}


