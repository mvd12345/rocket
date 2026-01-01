package org.example.config;

import sootup.core.model.SootMethod;
import sootup.core.types.ClassType;

import java.util.ArrayList;
import java.util.List;

public class SubclassErrorEntry {
    private String superClassType;
    private String className;
    private List<ClassType> subclasses;
    private List<SootMethod> methods;

    private String methodName;
    public SubclassErrorEntry(String superClassType, String className, List<ClassType> subclasses, String methodName) {
        this.superClassType = superClassType;
        this.className = className;
        this.subclasses = subclasses;
        this.methodName = methodName;
        this.methods = new ArrayList<>();
    }
    public void addMethod(SootMethod method) {
        this.methods.add(method);
    }
    public String getSuperClassType() {
        return superClassType;
    }

    public String getClassName() {
        return className;
    }
    public List<ClassType> getSubclasses() {
        return subclasses;
    }
    public List<SootMethod> getMethods() {
        return methods;
    }
    public String getMethodName(){
        return methodName;
    }

    @Override
    public String toString() {
        return "SubclassErrorEntry{" +
                "superClassType='" + superClassType + '\'' +
                ", className='" + className + '\'' +
                ", subclasses=" + subclasses +
                ", methods=" + methods +
                ", methodName='" + methodName + '\'' +
                '}';
    }
}
