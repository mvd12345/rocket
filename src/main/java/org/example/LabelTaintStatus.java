package org.example;

import org.example.config.VertexValue;
import sootup.core.jimple.basic.StmtPositionInfo;
import sootup.core.jimple.common.stmt.Stmt;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class LabelTaintStatus {
    private String methodName;
    private String className;
    private Set<VertexValue> compromisedVertices;
    private Stmt targetStmt;
    private StmtPositionInfo labelPosition; // New field

    public LabelTaintStatus(String methodName, String className, Set<VertexValue> compromisedVertices, Stmt targetStmt, StmtPositionInfo labelPosition) {
        this.methodName = methodName;
        this.className = className;
        this.compromisedVertices = new HashSet<>(compromisedVertices);
        this.targetStmt = targetStmt;
        this.labelPosition = labelPosition; // Initialize the new field
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public void setCompromisedVertices(Set<VertexValue> compromisedVertices) {
        this.compromisedVertices = compromisedVertices;
    }

    public void setTargetStmt(Stmt targetStmt) {
        this.targetStmt = targetStmt;
    }

    public void setLabelPosition(StmtPositionInfo labelPosition) {
        this.labelPosition = labelPosition;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getClassName() {
        return className;
    }

    public Set<VertexValue> getCompromisedVertices() {
        return compromisedVertices;
    }

    public Stmt getTargetStmt() {
        return targetStmt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof LabelTaintStatus that)) return false;
        return Objects.equals(methodName, that.methodName) && Objects.equals(className, that.className) && Objects.equals(compromisedVertices, that.compromisedVertices) && Objects.equals(targetStmt, that.targetStmt) && Objects.equals(labelPosition, that.labelPosition);
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodName, className, compromisedVertices, targetStmt, labelPosition);
    }

    public StmtPositionInfo getLabelPosition() {
        return labelPosition;
    }

}
