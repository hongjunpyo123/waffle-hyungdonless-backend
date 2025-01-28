package com.example.waffle_project.Service;

import com.example.waffle_project.Dto.UserDto;
import com.example.waffle_project.Entity.UserEntity;
import com.example.waffle_project.Repository.UserRepository;
import com.example.waffle_project.Utility.SmsUtil;
import com.example.waffle_project.Utility.Utility;
import jakarta.servlet.http.HttpSession;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@org.springframework.stereotype.Service
public class Service {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private Utility utility;

    @Autowired
    private SmsUtil smsUtil;

    @Autowired
    private HttpSession session; //세션 객체

    private BCryptPasswordEncoder hash = new BCryptPasswordEncoder();//비밀번호 저장을 위한 해쉬화 객체

    public Boolean saveUserInfo(UserDto userDto){
        try{
            if(userRepository.findByEmail(userDto.getEmail()) != null){ //회원이 이미 존재할 경우 예외처리
                return false;
            }
            userDto.setPassword(hash.encode(userDto.getPassword())); //비밀번호 해쉬화
            UserEntity userEntity = userRepository.save(userDto.toEntity());//회원정보 저장
            return true;
        } catch (Exception e){
            return false;
        }

    }

    public ResponseEntity<?> userFind(String email) {
        Map<String, String> response = new HashMap<>();
        UserEntity userEntity = userRepository.findByEmail(email); //email로 회원정보 조회
        if (userEntity == null) { //회원정보가 없을 경우
            response.put("error", "해당 이메일로 조회된 유저가 없습니다.");
            response.put("status", HttpStatus.BAD_REQUEST.toString());
            return ResponseEntity.badRequest().body(response);
        } else { //회원정보가 있을 경우
            return ResponseEntity.ok(userEntity.toDto());
        }
    }

    public List<UserDto> userFindAll(){
        List<UserEntity> userEntityList = userRepository.findAll(); //모든 회원정보 조회
        if(userEntityList.isEmpty()){//회원정보가 없을 경우
            return null;
        } else { //회원정보가 존재할 경우
            List<UserDto> userDtoList = userEntityList.stream().map(UserEntity::toDto).toList();//엔티티 리스트를 dto리스트로 변환
            return userDtoList;
        }
    }

    public ResponseEntity<?> userLogin(UserDto userDto){
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        UserEntity userEntity = userRepository.findByEmail(userDto.getEmail());
        if(userEntity == null){ //해당 이메일로 조회된 회원이 없다면
            response.put("error", "해당 이메일로 조회된 회원이 없습니다.");
            response.put("status", HttpStatus.BAD_REQUEST.toString());
            return ResponseEntity.badRequest().body(response);
        } else {
            if(hash.matches(userDto.getPassword(), userEntity.getPassword())){ //패스워드가 일치한다면
                String token;
                //token 발급 및 반환 로직
                String header = utility.encrypt(utility.getToday().plusDays(1).toString(),utility.getEncryptKey()); //만료일자는 오늘로부터 1일
                String payload = utility.encrypt(userDto.getEmail(), utility.getEncryptKey()); //이메일을 암호화한 값
                String signature = hash.encode(header + "/" + payload + "/" + utility.getTokenKey()); //header, payload, secretKey를 합쳐서 해쉬화
                token = header + "." + payload + "." + signature; //header, payload, signature를 합쳐서 토큰 생성
                response.put("token", token);
                response.put("status", HttpStatus.OK.toString());
                return ResponseEntity.ok(response);
            } else { //패스워드가 일치하지 않는다면
                response.put("error", "비밀번호가 일치하지 않습니다.");
                response.put("status", HttpStatus.UNAUTHORIZED.toString());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        }
    }

    public Boolean TokensIsValid(String token){ //토큰 유효성 검사
        String[] parts = token.split("\\.", 3);
        String header = utility.decrypt(parts[0], utility.getEncryptKey());
        if(utility.getToday().isBefore(LocalDate.parse(header))){ //토큰이 만료되었다면
            return false;
        }
        String payload = utility.decrypt(parts[1], utility.getEncryptKey());
        String signature = parts[2];
        if(hash.matches(header + "/" + payload + "/" + utility.getTokenKey(), signature)){
            return true;
        } else {
            return false;
        }
    }

    @Transactional
    public ResponseEntity<?> userDelete(String email) {
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        UserEntity userEntity = userRepository.findByEmail(email); //email로 회원정보 조회

        if (userEntity == null) {//회원정보가 없을 경우
            response.put("error", "해당 이메일로 조회된 유저가 없습니다.");
            response.put("status", HttpStatus.BAD_REQUEST.toString());
        } else { //회원정보가 있을 경우
            try{
                userRepository.deleteByEmail(email); //해당 이메일로 회원정보 삭제
                return ResponseEntity.ok(userEntity.toDto());
            } catch (Exception e) {//삭제에 실패했을 경우
                response.put("error", e.getMessage());
                response.put("status", HttpStatus.BAD_REQUEST.toString());
                return ResponseEntity.badRequest().body(response);
            }
        }
        return ResponseEntity.badRequest().body(response);
    }

    @Transactional
    public ResponseEntity<?> userUpdate(UserDto userDto){
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        UserEntity userEntity = userRepository.findByEmail(userDto.getEmail()); //email로 회원정보 조회
        if(userEntity == null){//회원정보가 없을 경우
            response.put("error", "해당 이메일로 조회된 회원이 없습니다.");
            response.put("status", HttpStatus.BAD_REQUEST.toString());
            return ResponseEntity.badRequest().body(response);
        } else {
            userDto.setPassword(hash.encode(userDto.getPassword())); //비밀번호 해쉬화
            userRepository.save(userDto.toEntity()); //회원정보 업데이트
            return ResponseEntity.ok(userDto);
        }

    }

    public ResponseEntity<?> sendSmsToFindEmail(UserDto userDto) {//메세지 보내는 부분
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        try {
            String name = userDto.getName();
            //수신번호 형태에 맞춰 "-"을 ""로 변환
            String phoneNum = userDto.getNumber().replaceAll("-", "");

            if (userRepository.findByEmail(userDto.getEmail()) != null) { //회원이 존재할 경우
                return ResponseEntity.badRequest().body("이미 회원이 존재합니다.");
            }

            String verificationCode = smsUtil.generateRandomCode(); //인증코드 4자리 생성
            session.setAttribute("code", verificationCode);
            session.setAttribute("name", userDto.getName());
            session.setAttribute("phoneNum", phoneNum);
            session.setAttribute("email", userDto.getEmail());
            //smsUtil.sendOne(phoneNum, verificationCode); //sms 전송 수행 코드 사용시 주석 해제
            response.put("verificationCode", verificationCode);
            response.put("status", HttpStatus.OK.toString());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("[sms/send Api error]\n에러 정보 : " + e.getMessage());

            response.put("error", e.getMessage());
            response.put("message", "number 값이 올바른지 확인하세요.");
            response.put("status", HttpStatus.BAD_REQUEST.toString());

            return ResponseEntity.badRequest().body(response);
        }
    }
}
