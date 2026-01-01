package org.example;
import sootup.core.jimple.basic.StmtPositionInfo;
import sootup.core.model.Position;
import java.util.Objects;

public class StmtPositionInfoWrapper {
    private final StmtPositionInfo stmtPositionInfo;

    public StmtPositionInfoWrapper(StmtPositionInfo stmtPositionInfo) {
        this.stmtPositionInfo = stmtPositionInfo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StmtPositionInfoWrapper that = (StmtPositionInfoWrapper) o;
        Position thisPosition = this.stmtPositionInfo.getStmtPosition();
        Position thatPosition = that.stmtPositionInfo.getStmtPosition();
        return Objects.equals(thisPosition.getFirstLine(), thatPosition.getFirstLine()) &&
                Objects.equals(thisPosition.getFirstCol(), thatPosition.getFirstCol()) &&
                Objects.equals(thisPosition.getLastLine(), thatPosition.getLastLine()) &&
                Objects.equals(thisPosition.getLastCol(), thatPosition.getLastCol());
    }

    @Override
    public int hashCode() {
        Position position = stmtPositionInfo.getStmtPosition();
        return Objects.hash(position.getFirstLine(), position.getFirstCol(), position.getLastLine(), position.getLastCol());
    }

    // Delegate methods to stmtPositionInfo as needed
    public StmtPositionInfo getStmtPositionInfo() {
        return stmtPositionInfo;
    }

    // Optionally, override toString or other methods for better logging or debugging
    @Override
    public String toString() {
        return "StmtPositionInfoWrapper{" +
                "stmtPositionInfo=" + stmtPositionInfo +
                '}';
    }
}
