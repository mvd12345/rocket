package org.example;

import sootup.core.frontend.OverridingBodySource;
import sootup.core.graph.MutableStmtGraph;
import sootup.core.jimple.Jimple;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.NoPositionInformation;
import sootup.core.jimple.basic.StmtPositionInfo;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.FallsThroughStmt;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JGotoStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.JNopStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.Body;
import sootup.core.model.FieldModifier;
import sootup.core.model.SootMethod;
import sootup.core.signatures.FieldSignature;
import sootup.core.types.ClassType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootField;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.OverridingJavaClassSource;
import sootup.java.core.views.JavaView;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Instruments the {@code isPositive(int)} method by recording calls and sign decisions.
 */
public final class Instrumentation {

    private Instrumentation() {
        // utility class
    }

    /**
     * Preconditions:
     *  - 'Trace' class with public static int fields: count, positive
     */
    public static void instrumentSignAndTrace(
            JavaView javaView,
            JavaSootClass sootClass,
            SootMethod sootMethod,
            String className,
            String methodName,
            List<Type> parameterTypes,
            Type returnType,
            Path outDir) {

        if (!"isPositive".equals(methodName)
                || parameterTypes.size() != 1
                || !PrimitiveType.getInt().equals(parameterTypes.get(0))
                || !PrimitiveType.getBoolean().equals(returnType)) {
            return; // not our target; no-op
        }

        Objects.requireNonNull(outDir, "outDir");

        final var identifierFactory = javaView.getIdentifierFactory();

        final JavaSootMethod jMethod = (JavaSootMethod) sootMethod;
        JavaSootClass targetClass = sootClass;

        // --- ensure: private String sign; ---
        final ClassType classType = identifierFactory.getClassType(className);
        final ClassType stringType = identifierFactory.getClassType("java.lang.String");
        final FieldSignature signFs = identifierFactory.getFieldSignature("sign", classType, stringType);

        if (!hasField(targetClass, signFs)) {
            JavaSootField signField =
                    new JavaSootField(signFs, EnumSet.of(FieldModifier.PRIVATE), List.of(), NoPositionInformation.getInstance());

            List<JavaSootField> updatedFields = new ArrayList<>(targetClass.getFields());
            updatedFields.add(signField);
            targetClass = targetClass.withFields(updatedFields);
        }

        final Body oldBody = Objects.requireNonNull(jMethod.getBody(), "Method has no body");

        // skip if instrumentation already present
        if (isAlreadyInstrumented(oldBody, identifierFactory)) {
            return;
        }

        final Body.BodyBuilder bodyBuilder = Body.builder(oldBody, jMethod.getModifiers());
        final MutableStmtGraph graph = bodyBuilder.getStmtGraph();
        final Stmt originalEntry = graph.getStartingStmt();

        final Local thisLocal = oldBody.getThisLocal();
        final Local paramLocal = oldBody.getParameterLocal(0);
        if (thisLocal == null || paramLocal == null) {
            return; // unexpected signature; bail out safely
        }

        final Local tempLocal = ensureTempLocal(bodyBuilder);
        final StmtPositionInfo noPos = StmtPositionInfo.getNoStmtPositionInfo();

        final ClassType traceType = identifierFactory.getClassType("Trace");
        final FieldSignature countFs =
                identifierFactory.getFieldSignature("count", traceType, PrimitiveType.getInt());
        final FieldSignature positiveFs =
                identifierFactory.getFieldSignature("positive", traceType, PrimitiveType.getInt());

        final JAssignStmt loadCount =
                Jimple.newAssignStmt(tempLocal, Jimple.newStaticFieldRef(countFs), noPos);
        final JAssignStmt incCountTmp =
                Jimple.newAssignStmt(tempLocal,
                        Jimple.newAddExpr(tempLocal, IntConstant.getInstance(1)), noPos);
        final JAssignStmt storeCount =
                Jimple.newAssignStmt(Jimple.newStaticFieldRef(countFs), tempLocal, noPos);

        final JIfStmt ifNegative =
                Jimple.newIfStmt(Jimple.newLtExpr(paramLocal, IntConstant.getInstance(0)), noPos);

        final JAssignStmt setPositive =
                Jimple.newAssignStmt(
                        Jimple.newInstanceFieldRef(thisLocal, signFs),
                        new StringConstant("positive", stringType),
                        noPos);

        final JAssignStmt loadPositive =
                Jimple.newAssignStmt(tempLocal, Jimple.newStaticFieldRef(positiveFs), noPos);
        final JAssignStmt incPositiveTmp =
                Jimple.newAssignStmt(tempLocal,
                        Jimple.newAddExpr(tempLocal, IntConstant.getInstance(1)), noPos);
        final JAssignStmt storePositive =
                Jimple.newAssignStmt(Jimple.newStaticFieldRef(positiveFs), tempLocal, noPos);

        final JGotoStmt gotoJoin = Jimple.newGotoStmt(noPos);
        final JAssignStmt setNegative =
                Jimple.newAssignStmt(
                        Jimple.newInstanceFieldRef(thisLocal, signFs),
                        new StringConstant("negative", stringType),
                        noPos);
        final JNopStmt join = Jimple.newNopStmt(noPos);

        graph.addNode(loadCount);
        graph.addNode(incCountTmp);
        graph.addNode(storeCount);
        graph.addNode(ifNegative);
        graph.addNode(setPositive);
        graph.addNode(loadPositive);
        graph.addNode(incPositiveTmp);
        graph.addNode(storePositive);
        graph.addNode(gotoJoin);
        graph.addNode(setNegative);
        graph.addNode(join);

        graph.setStartingStmt(loadCount);

        connect(graph, loadCount, incCountTmp);
        connect(graph, incCountTmp, storeCount);
        connect(graph, storeCount, ifNegative);

        graph.putEdge(ifNegative, JIfStmt.TRUE_BRANCH_IDX, setNegative);
        graph.putEdge(ifNegative, JIfStmt.FALSE_BRANCH_IDX, setPositive);
        connect(graph, ifNegative, setPositive);

        connect(graph, setPositive, loadPositive);
        connect(graph, loadPositive, incPositiveTmp);
        connect(graph, incPositiveTmp, storePositive);
        connect(graph, storePositive, gotoJoin);

        graph.putEdge(gotoJoin, JGotoStmt.BRANCH_IDX, join);
        connect(graph, setNegative, join);
        connect(graph, join, originalEntry);

        final Body newBody = bodyBuilder.build();
        final OverridingBodySource newBodySource =
                new OverridingBodySource(jMethod.getBodySource()).withBody(newBody);
        final JavaSootMethod overriddenMethod =
                jMethod.withOverridingMethodSource(old -> newBodySource);

        new OverridingJavaClassSource(targetClass.getClassSource())
                .withReplacedMethod(jMethod, overriddenMethod);
        // Intentionally omitting bytecode emission here; callers can decide how to persist the changes.
    }

    private static boolean isAlreadyInstrumented(Body body, sootup.core.IdentifierFactory idf) {
        final ClassType traceType = idf.getClassType("Trace");
        final FieldSignature countFs =
                idf.getFieldSignature("count", traceType, PrimitiveType.getInt());
        final Stmt entry = body.getStmtGraph().getStartingStmt();
        if (entry instanceof JAssignStmt assign && assign.getLeftOp() instanceof JStaticFieldRef staticRef) {
            return staticRef.getFieldSignature().equals(countFs);
        }
        return false;
    }

    private static Local ensureTempLocal(Body.BodyBuilder builder) {
        final String localName = "$robusta$temp";
        final Optional<Local> existing =
                builder.getLocals().stream().filter(loc -> localName.equals(loc.getName())).findFirst();
        if (existing.isPresent()) {
            return existing.get();
        }
        Local fresh = new Local(localName, PrimitiveType.getInt());
        builder.addLocal(fresh);
        return fresh;
    }

    private static void connect(MutableStmtGraph graph, Stmt from, Stmt to) {
        graph.putEdge((FallsThroughStmt) from, to);
    }

    private static boolean hasField(JavaSootClass cls, FieldSignature signature) {
        return cls.getFields().stream().anyMatch(field -> field.getSignature().equals(signature));
    }
}
