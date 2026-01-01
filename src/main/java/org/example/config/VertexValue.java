package org.example.config;

import java.util.Objects;

public class VertexValue {
    public String value;

    public VertexValue(String value) {
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VertexValue that = (VertexValue) o;
        return Objects.equals(value, that.value);
    }


    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
      /*  return "VertexValue{" +
                "value='" + value + '\'' +
                '}';*/
    }

}
