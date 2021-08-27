package com.myxinh.cusc.repository;

import com.myxinh.cusc.domain.Menu;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MenuRepository extends JpaRepository<Menu,Integer> {

    @Query("SELECT m FROM Menu m WHERE m.name = :menuName")
    Optional<Menu> findOneByMenuName(@Param("menuName") String menuName);
}
