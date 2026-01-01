package com.example.myapp.Tests;

public class Calculator {
    // Method that performs a calculation
    public void calculate(NumberWrapper num1, NumberWrapper num2) {
        // Call the addValues function with num1 and num2
        int result = addValues(num1, num2);

        int x = result + 7;
        int y = Taint.untaint(result + 17);

        String secret = null;

        if(num1.getValue() > 22){
            secret = num1.getType();
        }
        if(Taint.untaint(num1.getType().equals("secret"))){
            secret = num2.getType();
        }
        if(Taint.untaint(result > 7)){
            secret = "success";
        }
        if(result > 7){
            secret = "partial success";
        }
        if (x> 0) {
            secret = "xxx";
        }
        if(y > 0 ) {
            secret = "yyy";
        }
        // Update the value of num1 with the result
        num1.setValue(result);

        // Print the updated value of num1
        System.out.println("Updated value of num1: " + num1.getValue());
    }

    // Helper method to add values of two NumberWrapper objects
    private int addValues(NumberWrapper a, NumberWrapper b) {
        int cutoff = a.getValue();
        b.setValue(b.getValue() - cutoff);
        return b.getValue();
    }

    public static void main(String[] args) {
        // Create two NumberWrapper objects
        NumberWrapper num1 = new NumberWrapper(10);
        NumberWrapper num2 = new NumberWrapper(20);

        // Create a Calculator object
        Calculator calculator = new Calculator();

        // Perform calculation
        calculator.calculate(num1, num2);
    }
}

// Class representing a number wrapper
class NumberWrapper {
    private int value;

    private String type;

    // Constructor
    public NumberWrapper(int value) {
        this.value = value;
    }

    // Getter for value
    public int getValue() {
        return value;
    }

    // Setter for value
    public void setValue(int value) {
        this.value = value;
    }

    public String getType() {return  type;}

    public void setType(String type) { this.type = type;}
}