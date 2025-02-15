package com.example.waffle_project.Service;

import com.example.waffle_project.Dto.GoogleResponse;
import com.example.waffle_project.Dto.GoogleUserDto;
import com.example.waffle_project.Dto.OAuth2Response;
import com.example.waffle_project.Entity.GoogleUserEntity;
import com.example.waffle_project.Repository.GoogleUserRepository;
import com.example.waffle_project.Utility.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private GoogleUserRepository googleUserRepository;

    @Autowired
    private Utility utility;

    private GoogleUserDto googleUserDto = new GoogleUserDto();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //소셜로그인 엔드포인트 http://localhost:8080/oauth2/authorization/google
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); //로그인 서비스 제공자 구분
        OAuth2Response oAuth2Response = null;


        if(registrationId.equals("google")){ //제공자가 구글일 경우
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes()); //유저 데이터가 들어있는 객체
            GoogleUserEntity googleUserEntity = googleUserRepository.findByEmail(oAuth2Response.getEmail());
            if(googleUserEntity != null){ //이미 회원이 존재할 경우(로그인 로직)
                System.out.println("이미 회원이 존재합니다.");
            } else { //회원이 존재하지 않을 경우 (회원가입 로직)
                googleUserDto.setEmail(oAuth2Response.getEmail());
                googleUserDto.setName(oAuth2Response.getName());
                googleUserDto.setGoogleId(oAuth2Response.getProviderId());
                googleUserDto.setDate(utility.getToday().toString());
                googleUserRepository.save(googleUserDto.toEntity());
            }


        }
        String role = "ROLE_USER";
        return new com.example.waffle_project.Dto.OAuth2User(oAuth2Response, role);
    }
}
