package com.myxinh.cusc.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Set;

@Entity
@Table(name = "user")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {
    @Id
    @Column(name = "user_id",length = 37)
    private String userId;

    @Column(name = "username",length = 30,nullable = false,unique = true)
    private String username;

    @Column(name = "password",length = 60,nullable = false)
    private String password;

    @Column(name = "full_name",length = 50,nullable = false)
    private String fullName;

    private String sex;

    @Column(name = "created_date")
    private String createdDate;

    @Column(name = "last_modified_date")
    private String lastModifiedDate;

    private boolean active;

    @ManyToMany(fetch = FetchType.LAZY,
            cascade = {CascadeType.MERGE,CascadeType.REFRESH})
    @JoinTable(name="user_role",
            joinColumns = @JoinColumn(name ="user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    @JsonIgnore
    private Set<Role> roles;

    @OneToMany(mappedBy = "user",fetch = FetchType.LAZY,
            cascade = {CascadeType.MERGE,CascadeType.REFRESH})
    private Set<News> news;

    @OneToMany(mappedBy = "user",fetch = FetchType.LAZY)
    private Set<Lits> listLits;
}
