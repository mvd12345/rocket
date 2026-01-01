package com.example.myapp.Tests;

class ICSESyllabus implements PassCalculator {
    @Override
    public boolean calculatePass(String studentName, int year, int[] marks, int cutOff) {
        int totalMarks = 0;
        for (int mark : marks) {
            totalMarks += mark;
        }
        double percentage = (totalMarks / (double) (marks.length * 100)) * 100;
        return percentage > 50;
    }
}
