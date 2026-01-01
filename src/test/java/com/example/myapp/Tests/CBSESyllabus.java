package com.example.myapp.Tests;

class CBSESyllabus implements PassCalculator {
    @Override
    public boolean calculatePass(String studentName, int year, int[] marks, int cutOff) {
        int totalMarks = 0;
        for (int mark : marks) {
            totalMarks += mark;
        }
        double percentage = (totalMarks / (double) (marks.length * 100)) * 100;
        cutOff += (year/100) * totalMarks;
        return percentage > 45;
    }
}

