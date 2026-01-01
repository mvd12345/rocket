package com.example.myapp.Tests;

public class MemoryAccessTests {
    public static class Person {
        public String name;
        public int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }
    }

    public static class Counter {
        public static int count = 0;

        public static void increment() {
            count++;
        }
    }

    public static class BankAccount {
        private double balance;

        public BankAccount(double initialBalance) {
            this.balance = initialBalance;
        }

        public void deposit(double amount) {
            balance += amount;
        }

        public double getBalance() {
            return balance;
        }
    }

    public static void performMemoryAccessOperations() {
        // Example 1: Object Allocation and Field Access
        Person person = new Person("John Doe", 30);
        System.out.println(person.name + " is " + person.age + " years old.");

        // Example 2: Static Field Access
        Counter.increment();
        System.out.println("Count: " + Counter.count);

        // Example 3: Array Manipulation
        int[] numbers = new int[5];
        numbers[0] = 10;
        numbers[1] = 20;
        System.out.println("First element: " + numbers[0]);
        System.out.println("Second element: " + numbers[1]);

        // Example 4: Method Invocation and Object State Modification
        BankAccount account = new BankAccount(1000.0);
        account.deposit(500.0);
        System.out.println("Balance: " + account.getBalance());
    }

    public static void main(String[] args) {
        performMemoryAccessOperations(); // Calling the new method from main
    }
}
