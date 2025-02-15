package com.example.waffle_project.Dto;

import com.example.waffle_project.Entity.BoardCommentEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BoardCommentDto {
    private String writer; //작성자 이메일, pk
    private String nickname; //작성자 닉네임
    private String boardType; //게시판 타입
    private String content; //댓글 내용
    private Long likeCount; //하트
    private String createDate; //작성일

    public BoardCommentEntity toEntity(){
        BoardCommentEntity boardCommentEntity = new BoardCommentEntity();
        boardCommentEntity.setWriter(this.writer);
        boardCommentEntity.setNickname(this.nickname);
        boardCommentEntity.setBoardType(this.boardType);
        boardCommentEntity.setContent(this.content);
        boardCommentEntity.setLikeCount(this.likeCount);
        boardCommentEntity.setCreateDate(this.createDate);
        return boardCommentEntity;
    }
}
