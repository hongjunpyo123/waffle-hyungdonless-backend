package com.example.waffle_project.Repository;

import com.example.waffle_project.Entity.BoardEntity;
import com.example.waffle_project.Entity.BoardTypeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface BoardRepository extends JpaRepository<BoardEntity, Long> {
    @Query(value = "SELECT * FROM board_entity where board_type = :type", nativeQuery = true)
    List<BoardEntity> findByType(@Param("type") String type);

    @Query(value = "SELECT * FROM board_entity", nativeQuery = true)
    List<BoardEntity> findAll();
}
