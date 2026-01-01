package org.example;

import java.util.*;

import sootup.core.model.Body;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

/**
 * Scans a SootUp JavaView and builds:
 *   classFqcn -> list of (method, tag)
 * where tag is FUN_TRIGGER, FUN_UNTRIGGER, or NONE.
 * Also provides a utility to pull bodies for all funTrigger methods.
 */
public final class ProjectMethodAnnotationIndexer {

    private ProjectMethodAnnotationIndexer() {}

    // FQCNs of your method annotations
    private static final String ANN_FUN_TRIGGER   = "com.example.myapp.Tests.Taint$funTrigger";
    private static final String ANN_FUN_UNTRIGGER = "com.example.myapp.Tests.Taint$funUntrigger";

    /** The tag we attach to each method entry. */
    public enum MethodAnnoTag { FUN_TRIGGER, FUN_UNTRIGGER, NONE }

    /** A single annotated parameter declared inside @funTrigger.params(). */
    public static final class AnnotatedParam {
        public final int index;
        public final String type;
        public final String value;

        public AnnotatedParam(int index, String type, String value) {
            this.index = index;
            this.type = type;
            this.value = value;
        }

        @Override public String toString() {
            return "AnnotatedParam{index=" + index + ", type='" + type + "', value='" + value + "'}";
        }
    }

    /** A small DTO for each method we record. */
    public static final class MethodAnnoEntry {
        public final JavaSootMethod method; // underlying method reference
        public final MethodSignature signature;
        public final List<Type> parameterTypes;
        public final Type returnType;
        public final String subSignature;   // e.g., "void encrypt(byte[],int)"
        public final String name;           // method name (for convenience)
        public final MethodAnnoTag tag;
        public final List<AnnotatedParam> annotatedParams;

        public MethodAnnoEntry(JavaSootMethod method, MethodAnnoTag tag, List<AnnotatedParam> annotatedParams) {
            this.method = method;
            this.signature = method.getSignature();
            this.parameterTypes = List.copyOf(method.getParameterTypes());
            this.returnType = method.getReturnType();
            this.subSignature = signature.getSubSignature().toString();
            this.name = signature.getName();
            this.tag = tag;
            this.annotatedParams = List.copyOf(annotatedParams);
        }

        @Override public String toString() {
            return name + " :: " + tag + " :: " + subSignature + " :: params=" + annotatedParams;
        }
    }

    /**
     * Build the index: classFqcn -> list of (method, tag).
     * This version expects a JavaView (your 'javaProject').
     */
    public static Map<String, List<MethodAnnoEntry>> buildMethodAnnotationIndex(JavaView view) {
        final Map<String, List<MethodAnnoEntry>> out = new LinkedHashMap<>();
        final Optional<JavaView> viewOpt = Optional.of(view);

        // Iterate all classes in the analyzed project
        // If your SootUp version uses a different API, adapt this line:
        // e.g., for (JavaSootClass sc : view.getClasses()) { ... }
        for (JavaSootClass sc : view.getClasses()) {
            String classFqcn = sc.getType().getFullyQualifiedName();
            List<MethodAnnoEntry> entries = new ArrayList<>();

            for (JavaSootMethod jm : sc.getMethods()) {
                MethodClassification classification = classifyMethod(jm, viewOpt);
                entries.add(new MethodAnnoEntry(jm, classification.tag, classification.annotatedParams));
            }

            out.put(classFqcn, Collections.unmodifiableList(entries));
        }
        return Collections.unmodifiableMap(out);
    }

    /** Classify a single method by its annotations. */
    private static MethodClassification classifyMethod(JavaSootMethod jm, Optional<JavaView> viewOpt) {
        // Ask SootUp for method-level annotations
        Iterable<AnnotationUsage> anns;
        try {
            anns = jm.getAnnotations(viewOpt);
        } catch (Throwable t) {
            anns = List.of(); // be resilient
        }

        boolean hasTrigger   = false;
        boolean hasUntrigger = false;
        List<AnnotatedParam> annotatedParams = List.of();

        for (AnnotationUsage au : anns) {
            String t = au.getAnnotation().toString();
            if (ANN_FUN_TRIGGER.equals(t)) {
                hasTrigger = true;
                annotatedParams = parseAnnotatedParams(au);
            }
            if (ANN_FUN_UNTRIGGER.equals(t)) hasUntrigger = true;
        }

        if (hasTrigger)   return new MethodClassification(MethodAnnoTag.FUN_TRIGGER, annotatedParams);
        if (hasUntrigger) return new MethodClassification(MethodAnnoTag.FUN_UNTRIGGER, List.of());
        return new MethodClassification(MethodAnnoTag.NONE, List.of());
    }

    /**
     * Walk the index and retrieve Jimple bodies for every FUN_TRIGGER method.
     * Returns: classFqcn -> list of (subSignature, Body). Methods without bodies are skipped.
     */
    public static Map<String, List<Map.Entry<String, Body>>> collectFunTriggerBodies(
            JavaView view,
            Map<String, List<MethodAnnoEntry>> index
    ) {
        final Map<String, List<Map.Entry<String, Body>>> out = new LinkedHashMap<>();
        final Optional<JavaView> viewOpt = Optional.of(view);

        for (Map.Entry<String, List<MethodAnnoEntry>> e : index.entrySet()) {
            String classFqcn = e.getKey();
            List<MethodAnnoEntry> methods = e.getValue();

            // locate class
            var classType = view.getIdentifierFactory().getClassType(classFqcn);
            var scOpt = view.getClass(classType);
            if (scOpt.isEmpty()) continue;
            JavaSootClass sc = scOpt.get();

            // find funTrigger methods and retrieve bodies
            List<Map.Entry<String, Body>> bodies = new ArrayList<>();
            for (MethodAnnoEntry m : methods) {
                if (m.tag != MethodAnnoTag.FUN_TRIGGER) continue;

                JavaSootMethod jm = m.method;
                if (jm == null) continue;

                try {
                    Body b = jm.getBody();           // may throw for abstract/native
                    if (b != null) {
                        bodies.add(Map.entry(m.subSignature, b));
                    }
                } catch (Throwable ignore) {
                    // no concrete body; skip
                }
            }

            if (!bodies.isEmpty()) {
                out.put(classFqcn, Collections.unmodifiableList(bodies));
            }
        }
        return Collections.unmodifiableMap(out);
    }

    private static List<AnnotatedParam> parseAnnotatedParams(AnnotationUsage funTriggerUsage) {
        Map<String, Object> values = safeValues(funTriggerUsage);
        if (values == null) return List.of();

        Object paramsObj = values.get("params");
        if (paramsObj == null) return List.of();

        List<AnnotatedParam> out = new ArrayList<>();

        if (paramsObj instanceof List<?> list) {
            for (Object elem : list) {
                extractAnnotatedParam(elem).ifPresent(out::add);
            }
        } else {
            extractAnnotatedParam(paramsObj).ifPresent(out::add);
        }
        return List.copyOf(out);
    }

    private static Optional<AnnotatedParam> extractAnnotatedParam(Object elem) {
        if (elem instanceof AnnotationUsage nested) {
            Map<String, Object> nestedValues = safeValues(nested);
            return Optional.of(buildAnnotatedParam(nestedValues));
        }
        if (elem instanceof Map<?, ?> raw) {
            Map<String, Object> asMap = raw.entrySet().stream()
                    .filter(e -> e.getKey() instanceof String)
                    .collect(java.util.stream.Collectors.toMap(e -> (String) e.getKey(), Map.Entry::getValue));
            return Optional.of(buildAnnotatedParam(asMap));
        }
        return Optional.empty();
    }

    private static AnnotatedParam buildAnnotatedParam(Map<String, Object> values) {
        if (values == null) return new AnnotatedParam(-1, null, null);
        String type = asString(values.get("type"));
        String value = asString(values.get("value"));
        Integer idx = asInteger(values.get("index"));
        return new AnnotatedParam(idx != null ? idx : -1, type, value);
    }

    private static Map<String, Object> safeValues(AnnotationUsage usage) {
        try {
            Map<String, Object> values = usage.getValues();
            return values != null ? values : Map.of();
        } catch (Throwable t) {
            return Map.of();
        }
    }

    private static String asString(Object o) {
        if (o instanceof String s) return s;
        return (o != null) ? o.toString() : null;
    }

    private static Integer asInteger(Object o) {
        if (o instanceof Integer i) return i;
        if (o instanceof Number n) return n.intValue();
        if (o instanceof String s) {
            try { return Integer.parseInt(s); }
            catch (NumberFormatException ignored) { }
        }
        return null;
    }

    private static final class MethodClassification {
        final MethodAnnoTag tag;
        final List<AnnotatedParam> annotatedParams;

        MethodClassification(MethodAnnoTag tag, List<AnnotatedParam> annotatedParams) {
            this.tag = tag;
            this.annotatedParams = annotatedParams;
        }
    }
}
