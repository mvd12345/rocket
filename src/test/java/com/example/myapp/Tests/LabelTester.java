package com.example.myapp.Tests;

public class LabelTester {

    public static void testFunction(int Secret) {
        int k_1 = 0;

        while (k_1 != 0) {
            k_1 = Secret;
            k_1--;
        }
    }

    public static void main(String[] args) {
        // Example call to testFunction
        testFunction(5); // Adjust the values as needed for your tests
    }
}

