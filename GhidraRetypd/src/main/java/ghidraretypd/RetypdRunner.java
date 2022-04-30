package ghidraretypd;

import ghidra.util.Msg;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/** Runner for the ghidra-retypd executable */
public class RetypdRunner {
  private CommandLineOptions options;

  /** Constructor with a custom Python path */
  public RetypdRunner(CommandLineOptions options) {
    this.options = options;
  }

  /**
   * Run the ghidra-retypd executable with the loaded options
   *
   * @return List of output lines, if failed and outputOnFail is false, the list is empty
   * @throws Exception If option serialization fails, or execution fails, an exception is thrown
   */
  public List<String> run() throws Exception {
    ArrayList<String> command = new ArrayList<>();
    command.add("retypd-ghidra");
    command.addAll(options.serializeOptions());

    ProcessBuilder pb = new ProcessBuilder(command);
    pb.redirectErrorStream(true);

    Msg.info(this, "Executing command: " + String.join(" ", pb.command()));
    Process proc = pb.start();

    InputStreamReader inputReader = new InputStreamReader(proc.getInputStream());
    BufferedReader br = new BufferedReader(inputReader);
    ArrayList<String> output = new ArrayList<>();
    String line = null;
    while ((line = br.readLine()) != null) {
      output.add(line);
    }
    proc.waitFor();

    if (proc.exitValue() != 0) {
      throw new AnalysisException("Failed to execute ghidra-retypd:\n" + String.join("\n", output));
    }

    return output;
  }
}
