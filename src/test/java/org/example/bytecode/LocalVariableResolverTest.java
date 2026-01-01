package org.example.bytecode;

import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.assertTrue;

public class LocalVariableResolverTest {

    private static final String CLASSES_ROOT = "target/test-classes";
    private static final String CLASS_NAME = "com.example.myapp.Tests.BasicEncryptor";

    @Test
    public void testLocalVariableMetadataPresent() {
        assertTrue("Line number metadata missing", LocalVariableResolver.hasLineNumberMetadata(CLASSES_ROOT, CLASS_NAME));
        assertTrue("Local variable metadata missing", LocalVariableResolver.hasLocalVariableMetadata(CLASSES_ROOT, CLASS_NAME));
    }

    @Test
    public void testResolveLocalsForDecrypt() {
        Set<String> localsLine70 = LocalVariableResolver.resolve(CLASSES_ROOT, CLASS_NAME, "decrypt", 70);
        assertTrue("Expected local 'out' to be present", localsLine70.contains("out"));

        Set<String> localsLine73 = LocalVariableResolver.resolve(CLASSES_ROOT, CLASS_NAME, "decrypt", 73);
        assertTrue("Expected local 'idx2' to be present", localsLine73.contains("idx2"));
    }
}
