package com.bonnieapps.springsecurityapp2.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students/")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Hulk Nuke"),
            new Student(2, "Bonn Gun"),
            new Student(3, "Uro Nuke")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudents(@PathVariable("studentId") Integer studentId) {
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student "+studentId+" not found"));
    }
}