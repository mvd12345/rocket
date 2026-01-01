package org.example;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
public class UntriggerAnnotationParameters {
    private final List<Parameters> parametersList = new ArrayList<>();

    public List<Parameters> getParametersList() {
        return parametersList;
    }

    /** One sink entry from @Untrigger.Sink(type=..., value=..., index=...) */
    public static final class Parameters {
        private final int index;            // zero-based parameter index (or -1 if not applicable)
        private final String type;          // e.g., "java.lang.String" or "int"
        private final String variableName;  // source-level var name (may be null if not provided)

        public Parameters(int index, String type, String variableName) {
            this.index = index;
            this.type = type;
            this.variableName = variableName;
        }

        public int index() { return index; }
        public String type() { return type; }
        public String variableName() { return variableName; }

        @Override public String toString() {
            return "Parameters{index=" + index + ", type='" + type + "', variableName='" + variableName + "'}";
        }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Parameters that)) return false;
            return index == that.index &&
                    Objects.equals(type, that.type) &&
                    Objects.equals(variableName, that.variableName);
        }

        @Override public int hashCode() {
            return Objects.hash(index, type, variableName);
        }
    }

}
