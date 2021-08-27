package com.myxinh.cusc.repository;

import com.myxinh.cusc.domain.Lits;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface LitsRepository extends JpaRepository<Lits, Integer> {

    @Query("SELECT lits FROM Lits lits WHERE lits.lits_ten = :lits_name")
    Optional<Lits> findOneByName(@Param("lits_name") String lits_name);
}
