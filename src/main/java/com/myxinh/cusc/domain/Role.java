package com.myxinh.cusc.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "role")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Role {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private int roleId;

    @Column(name = "name",length = 15,nullable = false)
    private String name;
    @ManyToMany(mappedBy = "roles",fetch = FetchType.LAZY,
            cascade = {CascadeType.MERGE,CascadeType.REFRESH})
    private Set<UserEntity> users;


}
