/**
 * Retypd - machine code type inference Copyright (C) 2022 GrammaTech, Inc.
 *
 * <p>This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * <p>You should have received a copy of the GNU General Public License along with this program. If
 * not, see <https://www.gnu.org/licenses/>.
 */
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
