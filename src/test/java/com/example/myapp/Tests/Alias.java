package com.example.myapp.Tests;

// Define the Animal class with a method that takes an Animal object
class Animal {
    // Method that performs some action based on the input
    void performAction(Lion lion) {
        // Example action: check if the lion is tainted with a secret treat
        if (lion.isTainted()) {
            System.out.println("The lion has been tainted with " + lion.getTreat());
        } else {
            System.out.println("This lion has not been tainted.");
        }
    }
}

// Define the Lion class that extends Animal
class Lion extends Animal {
    private boolean tainted = false;
    private String treat = "";

    // Method to taint the lion with a secret treat
    void taintWithTreat(String treat) {
        this.tainted = true;
        this.treat = treat;
    }

    boolean isTainted() {
        return tainted;
    }

    String getTreat() {
        return treat;
    }
}

// Define the Alias class with the testAlias method
public class Alias {
    // Method that takes a string and demonstrates aliasing with Lion objects
    void testAlias(String secretTreat) {
        // Declare an object "a" for Animal class (though not used in your steps)
        Animal a = new Animal();

        // Declare an object "b" for Lion class
        Lion b = new Lion();

        // Assign the variable "b" to another object "c" of class Lion (creating alias)
        Lion c = b;

        // Taint the object "b" with "SecretTreat"
        b.taintWithTreat(secretTreat);

        // Pass the object "b" into a method in class Animal
        a.performAction(b);

        // Now pass the object "c" into the method in class Animal
        a.performAction(c);
    }

    public static void main(String[] args) {
        Alias alias = new Alias();
        alias.testAlias("SecretTreat");
    }
}

