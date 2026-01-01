package com.example.myapp.Tests;

import java.lang.annotation.*;

public class Taint {
    public boolean attribute;

    /* -------------------------
     * Field / attribute markers
     * ------------------------- */

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.FIELD})
    public @interface Trigger { }      // marker: tag attributes/fields only

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.FIELD})
    public @interface Untrigger { }    // marker: tag attributes/fields only


    /* -------------------------
     * Function annotations
     * ------------------------- */

    /**
     * Tag a method as a functional trigger AND specify which parameters
     * should be tainted (by index/type/name).
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface funTrigger {
        /**
         * Parameters to taint. Each entry identifies a parameter by:
         *  - index()  : zero-based parameter position
         *  - type()   : canonical type name (e.g., "byte[]", "java.lang.String")
         *  - value()  : source-level name, if available (for readability/reporting)
         */
        Parameters[] params();
    }

    /**
     * Tag a method as a functional untrigger (marker only).
     * Used to track that this method is explicitly marked non-triggering.
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface funUntrigger { } // marker: track method only, no params needed


    /* -------------------------
     * Shared parameter schema
     * ------------------------- */

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.METHOD, ElementType.PARAMETER})
    public @interface Parameters {
        String type();   // e.g., "byte[]", "int", "java.lang.String"
        String value();  // source name (optional; use "" if unknown)
        int index();     // 0-based parameter index
    }

    public static <T> T untaint(T value) { return value; }
    public static <T> T taint(T value) { return value; }
}
