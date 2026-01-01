package com.example.myapp.Tests;

class Student implements java.io.Serializable {
    String name;
    int year;

    public Student(String name, int year) {
        this.name = name;
        this.year = year;
    }

    public String getName() {
        return name;
    }

    public int getYear() {
        return year;
    }
}
