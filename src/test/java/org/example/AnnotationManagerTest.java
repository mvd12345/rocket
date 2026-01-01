package org.example;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import sootup.core.IdentifierFactory;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.Type;
import sootup.java.core.JavaIdentifierFactory;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class AnnotationManagerTest {

    private PrintStream originalOut;
    private ByteArrayOutputStream buffer;

    @Before
    public void setUp() {
        originalOut = System.out;
        buffer = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buffer));
    }

    @After
    public void tearDown() {
        System.setOut(originalOut);
    }

    @Test
    public void annotationManagerPrintsFieldAnnotations() throws Exception {
        String baseDir = Paths.get("demo", "HelloSootup").toString();
        JavaView view = HelloSootup.initializeSootUpFramework(baseDir);

        IdentifierFactory idFactory = view.getIdentifierFactory();
        ClassType classType = idFactory.getClassType("com.example.myapp.Tests.CTChainDemo");
        JavaSootClass sc = view.getClass(classType).orElseThrow();

        Type byteArrayType = Type.createArrayType(PrimitiveType.ByteType.getInstance(), 1);
        MethodSignature signature = idFactory.getMethodSignature(
                classType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(
                        "branchOnSecret",
                        PrimitiveType.BooleanType.getInstance(),
                        List.of(byteArrayType)
                )
        );

        JavaSootMethod method = (JavaSootMethod) view.getMethod(signature).orElseThrow();

        Method annotationManager = HelloSootup.class
                .getDeclaredMethod("annotationManager", JavaSootMethod.class, JavaSootClass.class);
        annotationManager.setAccessible(true);
        annotationManager.invoke(null, method, sc);

        String output = buffer.toString();
        assertTrue(output.contains("com.example.myapp.Tests.Taint$Trigger"));
        assertTrue(output.contains("com.example.myapp.Tests.Taint$Untrigger"));
    }
}
