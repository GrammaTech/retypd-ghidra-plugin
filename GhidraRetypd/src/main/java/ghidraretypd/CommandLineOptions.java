package ghidraretypd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Manage and serialize options for the bin2math executable */
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
   * @return Encoded arguments to be added to the list of arguments for use in bin2math
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
   * Serialize the options into a list of strings representing arguments to the bin2math executable
   *
   * @return The list of strings to pass to bin2math
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
