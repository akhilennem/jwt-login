package com.attendance.login.UserPackage.models;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Data
@Table(name="facebook")
public class Facebook {

    @Id
    public String identity;
    public String name;
    public String imageurl="null";

    public Facebook(String identity, String name, String imageurl) {
        this.identity=identity;
        this.name=name;
        this.imageurl=imageurl;
    }

    public Facebook() {

    }
}
