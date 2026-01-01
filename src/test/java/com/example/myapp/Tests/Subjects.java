package com.example.myapp.Tests;

class Subjects implements java.io.Serializable {
    String subjectName;
    int marks;

    public Subjects(String subjectName, int marks) {
        this.subjectName = subjectName;
        this.marks = marks;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public int getMarks() {
        return marks;
    }
}
