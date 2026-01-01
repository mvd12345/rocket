package org.example.config;

import lombok.Getter;
import lombok.Setter;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Value;
import sootup.core.types.Type;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class MethodVisitStatus {
    private final String pkgName;
    private final String className;
    private final String methodName;

    private final List<Type> types;
    private final Map<Integer, VertexValue> secretVertices;

    private  final List<Immediate> values;
    @Getter
    @Setter
    private boolean methodReturnStatus;
    private boolean returnDeclassifiedByUntrigger;
    private Map<Integer, String> methodParameterMapping;

    public MethodVisitStatus(String pkgName, String className, String methodName, List<Type> types, Map<Integer, VertexValue> secretVertices, List<Immediate> values) {
        this.pkgName = pkgName;
        this.className = className;
        this.methodName = methodName;
        this.types = types;
        this.secretVertices = secretVertices;
        this.values = values;

        this.methodReturnStatus = false;
        this.returnDeclassifiedByUntrigger = false;
        this.methodParameterMapping = new LinkedHashMap<>();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MethodVisitStatus)) return false;
        MethodVisitStatus that = (MethodVisitStatus) o;

        // Compare only positions (keys) of tainted arguments
        return Objects.equals(pkgName, that.pkgName)
                && Objects.equals(className, that.className)
                && Objects.equals(methodName, that.methodName)
                && Objects.equals(types, that.types)
                && Objects.equals(secretVertices.keySet(), that.secretVertices.keySet());
    }

    @Override
    public int hashCode() {
        // Include only the taint positions in the hash
        return Objects.hash(pkgName, className, methodName, types, secretVertices.keySet());
    }
    public boolean isMethodReturnStatus() { return this.methodReturnStatus; }
    public void setMethodReturnStatus(boolean methodReturnStatus) { this.methodReturnStatus = methodReturnStatus; }
    public boolean isReturnDeclassifiedByUntrigger() {
        return returnDeclassifiedByUntrigger;
    }

    public void setReturnDeclassifiedByUntrigger(boolean returnDeclassifiedByUntrigger) {
        this.returnDeclassifiedByUntrigger = returnDeclassifiedByUntrigger;
    }

    public Map<Integer, String> getMethodParameterMapping() {
        return methodParameterMapping;
    }

    public void setMethodParameterMapping(Map<Integer, String> methodParameterMapping) {
        if (methodParameterMapping == null) {
            this.methodParameterMapping = new LinkedHashMap<>();
        } else {
            this.methodParameterMapping = new LinkedHashMap<>(methodParameterMapping);
        }
    }
}
