package org.example.config;

import javax.annotation.Nonnull;
import java.util.*;

public class SecretVerticesWrapper {
    // Double Linked List for function stack
    private LinkedList<FunctionStack> functionLinkedList = new LinkedList<>();
    private int                       currIndex          = -1;

    public SecretVerticesWrapper(){}

    public SecretVerticesWrapper(@Nonnull FunctionStack functionStack) {
        if (functionStack == null) {
            throw new RuntimeException("null can't be added");
        }
        add(functionStack);
    }

    public void add(FunctionStack functionStack) {
        //add element at tail. 0, 1, 2,3,4,5,6,7
        functionLinkedList.add(functionStack);
        currIndex++;
    }

    public void removeTop() {
        if (currIndex < 0) {
            currIndex = -1;
            return;
        }
        FunctionStack fs = functionLinkedList.removeLast();
        if(fs.function.toString().equals("sign_picnic3")){
            System.out.println("debug");
        }
        System.out.println("removeTop ="  + fs);
        currIndex--;
    }

    public LinkedList<FunctionStack> getFunctionStackList() {
        return this.functionLinkedList;
    }

    public void addCalledFunctionSecretVerticesToTop(Set<String> calledFunctionSecretVertices) {
        if (currIndex < 0) {
            throw new EmptyStackException();
        }
        this.getFunctionStackList().get(currIndex).addCalledFunctionSecretVertices(calledFunctionSecretVertices);
    }

    public Map<Integer, VertexValue> getCallingFunctionCurrentSecretVertices() {
        if (currIndex == -1) return null;
        return functionLinkedList.get(currIndex).getCallingFunctionSecretVertices();
    }


    public Map<Integer, VertexValue> getCallingFunctionPreviousSecretVertices() {
        if (currIndex -1 == -1) return null;
        return functionLinkedList.get(currIndex - 1).getCallingFunctionSecretVertices();
    }

    public int getSizeOfCallingFunctionCurrentSecretVertices() {
        if (functionLinkedList.isEmpty()) {
            return  0;
        }
        FunctionStack functionStack = functionLinkedList.get(currIndex);
        return functionStack.getCallingFunctionSecretVertices() != null ? functionStack.getCallingFunctionSecretVertices().size() : 0;
    }

    public int getSizeOfCallingFunctionPreviousSecretVertices() {
        if (currIndex > 0) {
            FunctionStack functionStack = functionLinkedList.get(currIndex - 1);
            return functionStack.getCallingFunctionSecretVertices() != null ? functionStack.getCallingFunctionSecretVertices().size() : 0;
        }
        return 0;
    }

    public static class FunctionStack {
        private final String                    function;
        private final String                    className;
        private final Map<Integer, VertexValue> callingFunctionSecretVertices;

        private Set<String> calledFunctionSecretVertices;

        public FunctionStack(String function, String className, Map<Integer, VertexValue> secretVertices) {
            this.function = function;
            this.className = className;
            this.callingFunctionSecretVertices = secretVertices;
        }

        public String getFunction() {
            return function;
        }

        public String getClassName() {
            return className;
        }

        public Map<Integer, VertexValue> getCallingFunctionSecretVertices() {
            return callingFunctionSecretVertices;
        }

        public void addCalledFunctionSecretVertices(Set<String> calledFunctionSecretVertices) {
            if (this.calledFunctionSecretVertices == null) {
                this.calledFunctionSecretVertices = new HashSet<>();
            }
            this.calledFunctionSecretVertices.addAll(calledFunctionSecretVertices);
        }

        @Override
        public String toString() {
            return "FunctionStack{" +
                    "function='" + function + '\'' +
                    ", class='" + className + '\'' +
                    ", secretVertices=" + this.calledFunctionSecretVertices +
                    '}';
        }
    }
}
