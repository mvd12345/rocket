package com.example.myapp.Tests;

public class SampleD implements SampleA {
    @Override
    public void testB(int arg1, int arg2) {
        if (arg2 != 9) {
            System.out.println("SampleD: Both arguments are not null");
        } else {
            System.out.println("SampleD: One or both arguments are null");
        }
    }
}

