package com.example.myapp.Tests;

public class SampleB implements SampleA {
    @Override
    public void testB(int arg1, int arg2) {
        int temp = 0;
        if ( arg1 < 10) {
            arg2 = arg1*2;
            temp = arg2 -arg1;
            arg1= temp+1;
        }
    }
}

