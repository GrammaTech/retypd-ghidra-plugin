package ghidraretypd;

/** Used to report exceptions specific to analysis */
public class AnalysisException extends Exception {
  public AnalysisException(String msg) {
    super(msg);
  }
}
