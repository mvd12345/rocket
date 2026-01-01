package org.example;
import org.example.config.VertexValue;
import sootup.core.jimple.basic.StmtPositionInfo;
import sootup.core.jimple.common.stmt.Stmt;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
public class IfTaintStatus {
    private String methodName;
    private String className;
    private Set<VertexValue> compromisedVertices;
    private Stmt ifStmt; // The IF statement itself
    private StmtPositionInfo ifPosition; // Position information of the IF statement

    public IfTaintStatus(String methodName, String className, Set<VertexValue> compromisedVertices, Stmt ifStmt, StmtPositionInfo ifPosition) {
        this.methodName = methodName;
        this.className = className;
        this.compromisedVertices = new HashSet<>(compromisedVertices);
        this.ifStmt = ifStmt;
        this.ifPosition = ifPosition;
    }

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public Set<VertexValue> getCompromisedVertices() {
        return compromisedVertices;
    }

    public void setCompromisedVertices(Set<VertexValue> compromisedVertices) {
        this.compromisedVertices = compromisedVertices;
    }

    public Stmt getIfStmt() {
        return ifStmt;
    }

    public void setIfStmt(Stmt ifStmt) {
        this.ifStmt = ifStmt;
    }

    public StmtPositionInfo getIfPosition() {
        return ifPosition;
    }

    public void setIfPosition(StmtPositionInfo ifPosition) {
        this.ifPosition = ifPosition;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IfTaintStatus that)) return false;
        return Objects.equals(methodName, that.methodName) && Objects.equals(className, that.className) && Objects.equals(compromisedVertices, that.compromisedVertices) && Objects.equals(ifStmt, that.ifStmt) && Objects.equals(ifPosition, that.ifPosition);
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodName, className, compromisedVertices, ifStmt, ifPosition);
    }
}
