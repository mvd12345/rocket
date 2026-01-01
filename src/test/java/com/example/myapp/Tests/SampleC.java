package com.example.myapp.Tests;

public class SampleC implements SampleA {
    @Override
    public void testB(int arg1, int arg2) {
        if (arg2 != 10) {
            System.out.println("SampleC: arg2 is not null");
        } else {
            System.out.println("SampleC: arg2 is null");
        }
    }
}

