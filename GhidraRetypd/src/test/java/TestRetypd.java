/* ###
 * IP: REMATH
 *
 */

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.junit.Test;

public class TestRetypd {
  @Test
  public void testRetypdScriptIsAvailable() throws IOException, InterruptedException {
    try {
      Process proc = Runtime.getRuntime().exec("retypd-ghidra --help");
      proc.waitFor(30, TimeUnit.SECONDS);
      int exitVal = proc.exitValue();
      assert (exitVal == 0);
    } catch (IOException | InterruptedException e) {
      System.err.println(
          "retypd-ghidra did not execute properly.  "
              + "This is probably because it is not in your path.  "
              + "Did you activate the python virtual environment?");
      throw e;
    }
  }
}
