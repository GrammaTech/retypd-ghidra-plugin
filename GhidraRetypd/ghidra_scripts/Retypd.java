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
