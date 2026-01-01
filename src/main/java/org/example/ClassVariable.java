package org.example;

import java.util.Objects;

public class ClassVariable {

    private String className;
    private String fieldName;

    public ClassVariable(String className, String fieldName) {
        this.className = className;
        this.fieldName = fieldName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClassVariable that = (ClassVariable) o;
        return Objects.equals(className, that.className) && Objects.equals(fieldName, that.fieldName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(className, fieldName);
    }

    @Override
    public String toString() {
        return "ClassVariable{" +
                "className='" + className + '\'' +
                ", fieldName='" + fieldName + '\'' +
                '}';
    }
}
