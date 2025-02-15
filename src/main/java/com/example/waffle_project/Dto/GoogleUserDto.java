package com.example.waffle_project.Dto;

import com.example.waffle_project.Entity.GoogleUserEntity;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GoogleUserDto {
    private String email;
    private String name;
    private String googleId;
    private String date;

    public GoogleUserEntity toEntity(){
        GoogleUserEntity googleUserEntity = new GoogleUserEntity();
        googleUserEntity.setEmail(this.email);
        googleUserEntity.setName(this.name);
        googleUserEntity.setGoogleId(this.googleId);
        googleUserEntity.setDate(this.date);
        return googleUserEntity;
    }

}
