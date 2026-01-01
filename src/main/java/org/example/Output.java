package org.example;

import org.example.config.SecretVerticesWrapper;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.Position;

import java.util.*;

public class Output {
    private final String className;
    private final String methodName;
    private final Set<String> taintedInputs;
    private final List<SecretVerticesWrapper.FunctionStack> functionStackList;
    private final Position position;
    private Set<TaintedVariable> variables = new LinkedHashSet<>();

    public Output(String className,
                  String methodName,
                  Set<String> taintedInputs,
                  List<SecretVerticesWrapper.FunctionStack> functionStackList,
                  Position position) {
        this.className = className;
        this.methodName = methodName;
        this.taintedInputs = taintedInputs;
        this.functionStackList = new LinkedList<>(functionStackList);
        this.position = position;
    }

    public Output(String className,
                  String methodName,
                  Set<String> taintedInputs,
                  List<SecretVerticesWrapper.FunctionStack> functionStackList,
                  Set<TaintedVariable> variables,
                  Position position) {
        this.className = className;
        this.methodName = methodName;
        this.taintedInputs = taintedInputs;
        this.functionStackList = functionStackList;
        this.variables = variables;
        this.position = position;
    }

    public Set<String> getTaintedInputs() {
        return taintedInputs;
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public List<SecretVerticesWrapper.FunctionStack> getFunctionStackList() {
        return functionStackList;
    }

    public Set<TaintedVariable> getVariables() {
        return variables;
    }

    public Position getPosition() {
        return position;
    }

    public boolean stackContains(String className, String methodName) {
        if (functionStackList == null || functionStackList.isEmpty()) {
            return false;
        }
        for (SecretVerticesWrapper.FunctionStack stack : functionStackList) {
            if (Objects.equals(stack.getClassName(), className) && Objects.equals(stack.getFunction(), methodName)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "\nClass Name = " + className
                + "\nMethod Name = " + methodName
                + "\ntaintedInputs = " + taintedInputs
                + "\nFunctionStack = " + functionStackList
                + "\n" + variables;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Output output = (Output) o;
        return Objects.equals(className, output.className)
                && Objects.equals(methodName, output.methodName)
                && Objects.equals(taintedInputs, output.taintedInputs)
                && Objects.equals(functionStackList, output.functionStackList)
                && Objects.equals(variables, output.variables)
                && Objects.equals(position, output.position);
    }

    @Override
    public int hashCode() {
        return Objects.hash(className, methodName, taintedInputs, functionStackList, variables, position);
    }
}

class ArrayTaintedVariable {
    private final String index;
    private final String variable;
    private final String arrayVariable;

    public ArrayTaintedVariable(String index, String variable, String arrayVariable) {
        this.index = index;
        this.variable = variable;
        this.arrayVariable = arrayVariable;
    }

    public String getIndex() {
        return index;
    }

    public String getVariable() {
        return variable;
    }

    public String getArrayVariable() {
        return arrayVariable;
    }
}

class TaintedVariable {
    private final String className;
    private final String methodName;
    private final String variable;
    private final String type;
    private final boolean isIfStmt;
    private final String variableChaining;
    private final int lineNumber;
    private final boolean isArray;
    private final boolean isMulDiv;
    private final Stmt stmt;
    private final ArrayTaintedVariable arrayTaintedVariable;
    private final boolean isVul_Lib;
    private final Set<String> tracedSourceCandidates;
    private final Set<String> lineTableSourceCandidates;

    public TaintedVariable(String className,
                           String methodName,
                           String variable,
                           String type,
                           boolean isIfStmt,
                           int lineNumber,
                           String variableChaining,
                           boolean isArray,
                           ArrayTaintedVariable arrayTaintedVariable,
                           boolean isMulDiv,
                           Stmt stmt,
                           boolean isVul_Lib,
                           Set<String> tracedSourceCandidates,
                           Set<String> lineTableSourceCandidates) {
        this.className = className;
        this.methodName = methodName;
        this.variable = variable;
        this.type = type;
        this.isIfStmt = isIfStmt;
        this.variableChaining = variableChaining;
        this.lineNumber = lineNumber;
        this.isArray = isArray;
        this.arrayTaintedVariable = arrayTaintedVariable;
        this.isMulDiv = isMulDiv;
        this.stmt = stmt;
        this.isVul_Lib = isVul_Lib;
        this.tracedSourceCandidates = toImmutableSet(tracedSourceCandidates);
        this.lineTableSourceCandidates = toImmutableSet(lineTableSourceCandidates);
    }

    public TaintedVariable(String className,
                           String methodName,
                           String variable,
                           String type,
                           boolean isIfStmt,
                           int lineNumber,
                           String variableChaining,
                           boolean isMulDiv) {
        this(className, methodName, variable, type, isIfStmt, lineNumber, variableChaining, false, null, isMulDiv, null, false, Collections.emptySet(), Collections.emptySet());
    }

    public TaintedVariable(String className,
                           String methodName,
                           String variable,
                           String type,
                           boolean isIfStmt,
                           int lineNumber,
                           String variableChaining) {
        this(className, methodName, variable, type, isIfStmt, lineNumber, variableChaining, false, null, false, null, false, Collections.emptySet(), Collections.emptySet());
    }

    public boolean isArray() {
        return isArray;
    }

    public boolean isMulDiv() {
        return isMulDiv;
    }

    public boolean isVulLib() {
        return isVul_Lib;
    }

    public ArrayTaintedVariable getArrayTaintedVariable() {
        return arrayTaintedVariable;
    }

    public Set<String> getTracedSourceCandidates() {
        return tracedSourceCandidates;
    }

    public Set<String> getLineTableSourceCandidates() {
        return lineTableSourceCandidates;
    }

    public boolean isIfStmt() {
        return isIfStmt;
    }

    public String getVariableChaining() {
        return variableChaining;
    }

    public String getType() {
        return type;
    }

    public String getVariable() {
        return variable;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public Stmt getStmt() {
        return stmt;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getClassName() {
        return className;
    }

    public String getIssueAsString() {
        if (isIfStmt) {
            return "Control Flow";
        }
        if (isArray) {
            return "Memory Access";
        }
        if (isMulDiv) {
            return "Arithmetic Operation";
        }
        if (isVul_Lib) {
            return "Library Call";
        }
        return "No Error";
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        TaintedVariable that = (TaintedVariable) o;
        return isIfStmt == that.isIfStmt
                && lineNumber == that.lineNumber
                && isArray == that.isArray
                && isMulDiv == that.isMulDiv
                && isVul_Lib == that.isVul_Lib
                && Objects.equals(className, that.className)
                && Objects.equals(methodName, that.methodName)
                && Objects.equals(variable, that.variable)
                && Objects.equals(type, that.type)
                && Objects.equals(variableChaining, that.variableChaining)
                && Objects.equals(stmt, that.stmt)
                && Objects.equals(arrayTaintedVariable, that.arrayTaintedVariable)
                && Objects.equals(tracedSourceCandidates, that.tracedSourceCandidates)
                && Objects.equals(lineTableSourceCandidates, that.lineTableSourceCandidates);
    }

    @Override
    public int hashCode() {
        return Objects.hash(className, methodName, variable, type, isIfStmt, variableChaining, lineNumber, isArray, isMulDiv, stmt, arrayTaintedVariable, isVul_Lib, tracedSourceCandidates, lineTableSourceCandidates);
    }

    @Override
    public String toString() {
        if (isIfStmt) {
            return "\nPotential leak (Sec dep Control Flow) detected!!"
                    + "\nTaintedVariable : value = " + variable
                    + ", Branching = " + isIfStmt
                    + ", linenumber=" + lineNumber
                    + " type  = " + type
                    + ", VariableChaining  = " + variableChaining;
        }
        if (isArray) {
            return "\nPotential leak (Sec dep Mem Access) detected!! TaintedVariable : value = "
                    + variable + ", type  = " + type + ", linenumber=" + lineNumber + ", VariableChaining  = " + variableChaining;
        }
        if (isMulDiv) {
            return "\nPotential leak (Sec dep Arithmetic operation) detected!! TaintedVariable : value = "
                    + variable + ", type  = " + type + ", linenumber=" + lineNumber + ", VariableChaining  = " + variableChaining + ", Operation Stmt  = " + stmt;
        }
        if (isVul_Lib) {
            return "\nPotential leak (Sec dep Library Method call) detected!! TaintedVariable : value = "
                    + variable + ", type  = " + type + ", linenumber=" + lineNumber + ", VariableChaining  = " + variableChaining + ", Library Call  = " + stmt;
        }
        StringBuilder builder = new StringBuilder("\nTaintedVariable : value = ")
                .append(variable)
                .append(", type  = ").append(type)
                .append(", linenumber=").append(lineNumber)
                .append(", VariableChaining  = ").append(variableChaining);
        if (!tracedSourceCandidates.isEmpty()) {
            builder.append(", TracedSourceCandidates = ").append(tracedSourceCandidates);
        }
        if (!lineTableSourceCandidates.isEmpty()) {
            builder.append(", LineTableSourceCandidates = ").append(lineTableSourceCandidates);
        }
        return builder.toString();
    }

    private static Set<String> toImmutableSet(Set<String> input) {
        if (input == null || input.isEmpty()) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(input));
    }
}
