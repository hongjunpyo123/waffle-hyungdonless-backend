package com.example.waffle_project.Service;

import com.example.waffle_project.Dto.*;
import com.example.waffle_project.Entity.BoardEntity;
import com.example.waffle_project.Entity.BoardIsLikeEntity;
import com.example.waffle_project.Entity.UserEntity;
import com.example.waffle_project.Repository.*;
import com.example.waffle_project.Utility.SmsUtil;
import com.example.waffle_project.Utility.Utility;
import jakarta.servlet.http.HttpSession;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class BoardService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BoardRepository boardRepository;

    @Autowired
    private BoardTypeRepository boardTypeRepository;

    @Autowired
    private BoardCommentRepository boardCommentRepository;

    @Autowired
    private ChatBotMessageRepository chatBotMessageRepository;

    @Autowired
    private BoardIsLikeRepository boardIsLikeRepository;

    @Autowired
    private CommentIsLikeRepository commentIsLikeRepository;

    @Autowired
    private Utility utility;

    @Autowired
    private SmsUtil smsUtil;

    @Autowired
    private HttpSession session; //세션 객체

    @Autowired
    private BCryptPasswordEncoder hash; //비밀번호 저장을 위한 해쉬화 객체

    @Autowired
    private ResourceLoader resourceLoader; //파일 저장을 위한 리소스 로더

    public ResponseEntity<?> createBoard(BoardDto boardDto, MultipartFile file) {
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        String filePath;
        System.out.println("createBoard 메서드 실행");
        if (file != null && !file.isEmpty()) //file이 존재할 경우 처리
        {
            try { //이미지파일 업로드 예외처리
                System.out.println("이미지 처리 로직 실행");
                String fileName = file.getOriginalFilename(); //파일 이름
                Resource resource = resourceLoader.getResource("classpath:static/images");
                String uploadDir = resource.getFile().getAbsolutePath();
                filePath = "/images/" + fileName;
                file.transferTo(new File(uploadDir + File.separator + fileName));

                boardDto.setImageURL(filePath); //이미지 파일 경로 저장

            } catch (Exception e) {
                response.put("error", e.getMessage());
                response.put("message", "이미지 저장에 실패하였습니다.");
                response.put("status", HttpStatus.BAD_REQUEST.toString());

                return ResponseEntity.badRequest().body(response);
            }
        } else{
            filePath = null; //이미지 파일이 없을 경우 null로 초기화
            boardDto.setImageURL(filePath); //이미지 파일 경로 저장
        }

        boardDto.setCommentCount(0l); //게시물 등록 시 댓글 수 0으로 초기화
        boardDto.setCreateDate(utility.getToday().toString());
        boardDto.setLikeCount(0l); //게시물 등록 시 좋아요 수 0으로 초기화
        boardDto.setView(0l); //게시물 등록 시 조회수 0으로 초기화

        boardRepository.save(boardDto.toEntity()); //게시물 저장

        response.put("message", "게시물 등록에 성공하였습니다.");
        response.put("status", HttpStatus.OK.toString());
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<?> getBoards_TYPE(String boardType){
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        List<BoardEntity> boardEntityList = boardRepository.findByType(boardType); //게시물 타입별 조회
        List<BoardDto> boardDtoList;
        BoardIsLikeEntity boardIsLikeEntity;

        String userEmail;
        try { //비로그인 상태 예외처리
            System.out.println("로그인 상태");
            userEmail = session.getAttribute("USER_EMAIL").toString();
        } catch (Exception e){
            System.out.println("비로그인 상태");
            userEmail = "비로그인 상태";
        }

        if(boardEntityList.isEmpty()){
            response.put("message", "[" + boardType + "] 해당 게시판에 게시물이 존재하지 않습니다.");
            response.put("status", HttpStatus.OK.toString());
            return ResponseEntity.ok(response);
        } else {
            boardDtoList = boardEntityList.stream().map(BoardEntity::toDto).toList();

            for(BoardDto boardDto : boardDtoList) {
                boardIsLikeEntity = boardIsLikeRepository.findByBoardIdAndEmail(boardDto.getId(), userEmail);
                if(boardIsLikeEntity == null){ //해당 게시물에 좋아요를 누른적이 없는 경우
                    boardDto.setIsLike("false");
                } else {
                    boardDto.setIsLike("true");
                }
            }

            return ResponseEntity.ok(boardDtoList);
        }
    }

    public ResponseEntity<?> getBoards_ALL(){
        Map<String, String> response = new HashMap<>(); //json 응답을 위한 맵
        List<BoardEntity> boardEntityList = boardRepository.findAll(); //게시물 타입별 조회
        List<BoardDto> boardDtoList;
        BoardIsLikeEntity boardIsLikeEntity;

        String userEmail;
        try { //비로그인 상태 예외처리
            System.out.println("로그인 상태");
            userEmail = session.getAttribute("USER_EMAIL").toString();
        } catch (Exception e){
            System.out.println("비로그인 상태");
            userEmail = "비로그인 상태";
        }


        if(boardEntityList.isEmpty()){
            response.put("message", "게시판에 게시물이 존재하지 않습니다.");
            response.put("status", HttpStatus.OK.toString());
            return ResponseEntity.ok(response);
        } else {
            boardDtoList = boardEntityList.stream().map(BoardEntity::toDto).toList();

            for(BoardDto boardDto : boardDtoList) {
                //좋아요 여부 확인하는 로직
                boardIsLikeEntity = boardIsLikeRepository.findByBoardIdAndEmail(boardDto.getId(), userEmail);
                if(boardIsLikeEntity == null){ //해당 게시물에 좋아요를 누른적이 없는 경우
                    boardDto.setIsLike("false");
                } else {
                    boardDto.setIsLike("true");
                }
            }

            return ResponseEntity.ok(ResponseDto.response(HttpStatus.OK, "게시물 조회 성공", boardDtoList));
        }
    }

    public ResponseEntity<?> getBoard(Long id){
        BoardEntity boardEntity = boardRepository.findById(id).orElse(null);
        BoardIsLikeEntity boardIsLikeEntity;

        String userEmail;
        try { //비로그인 상태 예외처리
            userEmail = session.getAttribute("USER_EMAIL").toString();
            System.out.println("로그인 상태 : " + userEmail);
        } catch (Exception e){
            System.out.println("비로그인 상태");
            userEmail = "비로그인 상태";
        }

        if(boardEntity == null){//아이디로 조회된 게시물이 없을 때
            return ResponseEntity.badRequest()
                    .body(ResponseDto.response(HttpStatus.BAD_REQUEST, "게시물이 존재하지 않습니다", null));
        } else {
            System.out.println("boardIsLikeEntity : " + id);
            System.out.println("boardIsLikeEntity : " + userEmail);
            boardIsLikeEntity = boardIsLikeRepository.findByBoardIdAndEmail(id, userEmail);
            BoardDto boardDto = boardEntity.toDto();
            if(boardIsLikeEntity == null){ //해당 게시물에 좋아요를 누른적이 없는 경우
                boardDto.setIsLike("false");
            } else {
                boardDto.setIsLike("true");
            }
            return ResponseEntity
                    .ok(ResponseDto.response(HttpStatus.OK, "게시물 조회 성공", boardDto));

        }
    }

    public ResponseEntity<?> IsLikeBoard(BoardIsLikeDto boardIsLikeDto){
        try { //비로그인 상태 예외처리
            session.getAttribute("USER_EMAIL").toString();
            System.out.println("[IsLikeBoard]로그인 상태");
        } catch (Exception e){
            System.out.println("[IsLikeBoard]비로그인 상태");
            return ResponseEntity.badRequest()
                    .body(ResponseDto.response(HttpStatus.BAD_REQUEST, "로그인이 필요한 서비스입니다", null));
        }


        //해당 유저가 이미 좋아요를 눌렀는지 아닌지 판단하는 로직
        BoardIsLikeEntity boardIsLikeEntity;
        String userEmail = session.getAttribute("USER_EMAIL").toString();

        boardIsLikeEntity = boardIsLikeRepository.findByBoardIdAndEmail(boardIsLikeDto.getBoardId(), userEmail);

        if(boardIsLikeEntity != null){ //이미 좋아요를 눌렀을 경우
            boardIsLikeRepository.DeleteByBoardIdAndEmail(boardIsLikeDto.getBoardId(), userEmail); //좋아요 취소
            return ResponseEntity.ok()
                    .body(ResponseDto.response(HttpStatus.OK, "게시판 좋아요 삭제에 성공하였습니다", null));
        }

        try{
            boardIsLikeRepository.save(boardIsLikeDto.toEntity());
            return ResponseEntity.ok()
                    .body(ResponseDto.response(HttpStatus.OK, "게시판 좋아요 등록에 성공하였습니다", null));
        } catch (Exception e) {
            System.out.println("오류 메세지 : " + e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ResponseDto.response(HttpStatus.BAD_REQUEST, "게시판 좋아요 등록에 실패하였습니다", null));
        }
    }

    public ResponseEntity<?> IsLikeComment(CommentIsLikeDto commentIsLikeDto){
        try{
            commentIsLikeRepository.save(commentIsLikeDto.toEntity());
            return ResponseEntity.ok()
                    .body(ResponseDto.response(HttpStatus.OK, "댓글 좋아요 등록에 성공하였습니다", commentIsLikeDto));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(ResponseDto.response(HttpStatus.BAD_REQUEST, "댓글 좋아요 등록에 실패하였습니다", null));
        }
    }

}
