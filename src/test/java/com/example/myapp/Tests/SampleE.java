package com.example.myapp.Tests;

public class SampleE extends SampleC {
    @Override
    public void testB(int arg1, int arg2) {
        if ( arg1 == 10) {
            System.out.println("SampleE: arg1 is not null");
        } else {
            System.out.println("SampleE: arg1 is null");
        }
    }
}

