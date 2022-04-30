/* IP: GrammaTech, Inc.
 * REVIEWED: NO
 * Copyright GrammaTech, Inc 2022
 * All Rights Reserved
 */

// Script to perform type analysis on a binary

// @category Functions
// @author GrammaTech, Inc.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FunctionManager;
import ghidraretypd.AnalysisException;
import ghidraretypd.CommandLineOptions;
import ghidraretypd.RetypdGenerate;
import ghidraretypd.RetypdRunner;
import ghidraretypd.RetypdTypes;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Retypd extends GhidraScript {

  @Override
  protected void run() throws Exception {
    try {
      Path tmpDir = Files.createTempDirectory("retypd");
      Path jsonFilename = Paths.get(tmpDir.toString(), "bin.json");
      writer.println("Writing JSON output to " + jsonFilename.toString());

      RetypdGenerate retypd = new RetypdGenerate(currentProgram);
      Files.writeString(jsonFilename, retypd.getJSON());

      CommandLineOptions retypdOptions = new CommandLineOptions();
      retypdOptions.setArgument("json-in", jsonFilename);

      RetypdRunner runner = new RetypdRunner(retypdOptions);
      try {
        runner.run();
      } catch (Exception e) {
        throw new AnalysisException("Failed to execute Retypd executable: " + e);
      }
      writer.println("Loading inferred types");
      RetypdTypes types =
          RetypdTypes.loadTypes(
              jsonFilename.resolveSibling(jsonFilename.getFileName() + ".types.json"), writer);
      writer.println("Updating function prototypes");
      FunctionManager funcMgr = currentProgram.getFunctionManager();
      types.updateFunctions(funcMgr, currentProgram.getDataTypeManager(), writer);

    } catch (IOException | AnalysisException e) {
      println("ERROR:  " + e.getMessage());
      return;
    }
  }
}
