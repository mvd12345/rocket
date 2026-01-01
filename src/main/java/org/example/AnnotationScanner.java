package org.example;

import org.example.config.MethodSignatureConfigLoader;

import java.util.*;
import sootup.core.IdentifierFactory;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.Type;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

public final class AnnotationScanner {
    private AnnotationScanner() {}

    // Binary names for the *function* annotations
    private static final String FUN_TRIGGER_BIN    = "com.example.myapp.Tests.Taint$funTrigger";
    private static final String FUN_UNTRIGGER_BIN  = "com.example.myapp.Tests.Taint$funUntrigger";

    /* =========================================================
     * Untrigger (function)  — called exactly as before
     * ========================================================= */
    public static void scanMethodBodyForUntrigger(
            JavaView view,
            MethodSignatureConfigLoader.MethodConfig methodConfig,
            List<Type> parameterTypes,
            Type returnType,
            UntriggerAnnotationParameters outSinkParams
    ) {
        JavaSootMethod jMethod = resolveMethod(view, methodConfig, parameterTypes, returnType);

        // METHOD-LEVEL funUntrigger
        for (AnnotationUsage au : jMethod.getAnnotations(Optional.of(view))) {
            maybeCollectFunUntrigger(au, outSinkParams, FUN_UNTRIGGER_BIN, -1);
        }

        // PARAMETER-LEVEL funUntrigger
        int paramCount = parameterTypes.size();
        for (int i = 0; i < paramCount; i++) {
            for (AnnotationUsage au : getParamAnnotationsPortable(jMethod, i, view)) {
                maybeCollectFunUntrigger(au, outSinkParams, FUN_UNTRIGGER_BIN, i);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void maybeCollectFunUntrigger(
            AnnotationUsage au,
            UntriggerAnnotationParameters outSinkParams,
            String funUntriggerBinaryName,
            int fallbackIndex
    ) {
        if (!funUntriggerBinaryName.equals(au.getAnnotation().getClassName())) return;

        Map<String, Object> values = au.getValues();
        if (values == null) return;

        Object sinkArray = values.get("sinkMethod");       // same schema as before
        Object sourceObj = values.get("sourceMethod");     // single nested @Parameters

        // Optional: you can use sourceObj for validations/reporting if needed.

        if (sinkArray instanceof List<?> list) {
            for (Object elem : list) {
                if (!(elem instanceof Map<?, ?> raw)) continue;
                Map<String, Object> m = (Map<String, Object>) raw;

                String type = (m.get("type") instanceof String s) ? s : null;
                String name = (m.get("value") instanceof String s) ? s : null;
                Integer idx = (m.get("index") instanceof Number n) ? n.intValue()
                        : (m.get("index") instanceof String s ? tryParseInt(s) : null);
                int index = (idx != null ? idx : fallbackIndex);

                if (type != null || name != null || index >= 0) {
                    outSinkParams.getParametersList()
                            .add(new UntriggerAnnotationParameters.Parameters(index, type, name));
                }
            }
        }
    }

    /* =========================================================
     * Trigger (function) — called exactly as before
     * ========================================================= */
    public static void scanMethodBodyForTrigger(
            JavaView view,
            MethodSignatureConfigLoader.MethodConfig methodConfig,
            List<Type> parameterTypes,
            Type returnType,
            TriggerAnnotationParameters outTriggerParams
    ) {
        JavaSootMethod jMethod = resolveMethod(view, methodConfig, parameterTypes, returnType);

        // METHOD-LEVEL funTrigger
        for (AnnotationUsage au : jMethod.getAnnotations(Optional.of(view))) {
            maybeCollectFunTrigger(au, outTriggerParams, FUN_TRIGGER_BIN, -1);
        }

        // PARAMETER-LEVEL funTrigger
        int paramCount = parameterTypes.size();
        for (int i = 0; i < paramCount; i++) {
            for (AnnotationUsage au : getParamAnnotationsPortable(jMethod, i, view)) {
                maybeCollectFunTrigger(au, outTriggerParams, FUN_TRIGGER_BIN, i);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void maybeCollectFunTrigger(
            AnnotationUsage au,
            TriggerAnnotationParameters outParams,
            String funTriggerBinaryName,
            int fallbackIndex
    ) {
        if (!funTriggerBinaryName.equals(au.getAnnotation().getClassName())) return;

        Map<String, Object> values = au.getValues();
        if (values == null) return;

        Object sinkArray = values.get("sinkMethod");
        Object sourceObj = values.get("sourceMethod");

        if (sinkArray instanceof List<?> list) {
            for (Object elem : list) {
                if (!(elem instanceof Map<?, ?> raw)) continue;
                Map<String, Object> m = (Map<String, Object>) raw;

                String type = (m.get("type") instanceof String s) ? s : null;
                String name = (m.get("value") instanceof String s) ? s : null;
                Integer idx = (m.get("index") instanceof Number n) ? n.intValue()
                        : (m.get("index") instanceof String s ? tryParseInt(s) : null);
                int index = (idx != null ? idx : fallbackIndex);

                if (type != null || name != null || index >= 0) {
                    outParams.getParametersList()
                            .add(new TriggerAnnotationParameters.Parameters(index, type, name));
                }
            }
        }
    }

    /* ========================= Shared helpers ========================= */

    private static JavaSootMethod resolveMethod(
            JavaView view,
            MethodSignatureConfigLoader.MethodConfig methodConfig,
            List<Type> parameterTypes,
            Type returnType
    ) {
        IdentifierFactory idf = view.getIdentifierFactory();
        ClassType classType = idf.getClassType(methodConfig.className);
        JavaSootClass jClass = view.getClass(classType)
                .orElseThrow(() -> new IllegalStateException("Class not found: " + methodConfig.className));

        MethodSignature sig = idf.getMethodSignature(classType, methodConfig.methodName, returnType, parameterTypes);
        return (JavaSootMethod) view.getMethod(sig)
                .orElseThrow(() -> new IllegalStateException("Method not found: " + sig));
    }

    @SuppressWarnings("unchecked")
    private static List<AnnotationUsage> getParamAnnotationsPortable(JavaSootMethod m, int index, JavaView view) {
        try {
            var method = m.getClass().getMethod("getParameterAnnotations", int.class, Optional.class);
            Object res = method.invoke(m, index, Optional.of(view));
            return (List<AnnotationUsage>) res;
        } catch (NoSuchMethodException ignored) {
            try {
                var method = m.getClass().getMethod("getParameterAnnotations", int.class);
                Object res = method.invoke(m, index);
                return (List<AnnotationUsage>) res;
            } catch (NoSuchMethodException ignored2) {
                try {
                    var method = m.getClass().getMethod("getParameterAnnotations", Optional.class);
                    Object res = method.invoke(m, Optional.of(view));
                    List<List<AnnotationUsage>> outer = (List<List<AnnotationUsage>>) res;
                    return (index >= 0 && index < outer.size()) ? outer.get(index) : List.of();
                } catch (NoSuchMethodException ignored3) {
                    try {
                        var method = m.getClass().getMethod("getParameterAnnotations");
                        Object res = method.invoke(m);
                        List<List<AnnotationUsage>> outer = (List<List<AnnotationUsage>>) res;
                        return (index >= 0 && index < outer.size()) ? outer.get(index) : List.of();
                    } catch (Exception e4) { return List.of(); }
                } catch (Exception e3) { return List.of(); }
            } catch (Exception e2) { return List.of(); }
        } catch (Exception e) { return List.of(); }
    }

    private static Integer tryParseInt(String s) {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return null; }
    }
}
