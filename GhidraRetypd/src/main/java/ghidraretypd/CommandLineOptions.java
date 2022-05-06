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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Manage and serialize options for a command line utility */
public class CommandLineOptions {
  private Map<String, Object> arguments;

  public CommandLineOptions() {
    arguments = new HashMap<>();
  }

  /**
   * Set an argument to a given value.
   *
   * @param argument Name of the argument (after the -- in the option name, for example
   *     --option-here would be passed as option-here)
   * @param data Data to be encoded for that argument
   */
  public void setArgument(String argument, Object data) {
    arguments.put(argument, data);
  }

  /**
   * Serialize an (argument, value) pair to a list of arguments to use
   *
   * @param argument Argument name to pass
   * @param data Object to encode as the value
   * @return Encoded arguments to be added to the list of arguments for use in the command line
   */
  private List<String> serializeObject(String argument, Object data) {
    List<String> output = new ArrayList<>();

    if (data instanceof List<?>) {
      for (Object subObject : (List<?>) data) {
        output.add("--" + argument);
        output.add(subObject.toString());
      }
    } else {
      if (argument != null) {
        output.add("--" + argument);
      }

      if (data != null) {
        output.add(data.toString());
      }
    }

    return output;
  }

  /**
   * Serialize the options into a list of strings representing arguments to the command line
   *
   * @return The list of strings to pass to the command line
   */
  public List<String> serializeOptions() throws Exception {
    ArrayList<String> output = new ArrayList<>();

    for (String arg : arguments.keySet()) {
      // Skip positional arguments here
      if (arg.equals("binary")) {
        continue;
      }

      output.addAll(serializeObject(arg, arguments.get(arg)));
    }

    output.addAll(serializeObject(null, arguments.get("binary")));

    return output;
  }
}
