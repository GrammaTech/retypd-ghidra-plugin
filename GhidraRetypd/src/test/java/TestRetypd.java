/* ###
 * IP: REMATH
 *
 */

import static org.junit.Assert.*;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.project.test.TestProjectManager;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import utility.application.ApplicationLayout;

public class TestRetypd {
  static String TEST_DIR;

  static {
    TEST_DIR = Paths.get("src/test/resources/").toAbsolutePath().toString();
  }

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

  /**
   * Open a Ghidra project at a given location
   *
   * @param directory Directory that holds the project
   * @param project Project being opened
   * @return Loaded Project object
   * @throws Exception Thrown on error finding/loading project
   */
  public static Project openProject(String directory, String project) throws Exception {
    ApplicationLayout layout = new GhidraApplicationLayout();
    ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
    if (!Application.isInitialized()) {
      Application.initializeApplication(layout, configuration);
    }

    ProjectManager manager = TestProjectManager.get();
    ProjectLocator projectLocator = new ProjectLocator(directory, project);
    Project ret = manager.openProject(projectLocator, false, true);
    if (ret == null) {
      System.err.println("Unable to open project.  Check that Ghidra is not already running.");
    }
    assert (ret != null);
    return ret;
  }

  /**
   * Load a Program instance from a given file
   *
   * @param project Loaded Ghidra project object
   * @param filename File name of the program to load
   * @param consumer Object which is consuming the loaded Program
   * @return Program loaded from the given Project
   * @throws Exception
   */
  public static Program getProgram(Project project, String filename, Object consumer)
      throws Exception {
    DomainFolder domFolder = project.getProjectData().getRootFolder();
    DomainFile file = domFolder.getFile(filename);
    assert (file != null);
    Program program = (Program) file.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
    return program;
  }

  @Test
  public void testRetypdProject() throws Exception {
    Project project = openProject(TEST_DIR, "test-project");

    try {
      Program program = getProgram(project, "test-structs-hf", this);
      assert (program != null);
    } finally {
      project.close();
    }
  }

  /**
   * Get a Ghidra script from the currently loaded script files
   *
   * @param scriptName Name of the script file to load (.java)
   * @return GhidraScript instance with that files contents
   * @throws Exception
   */
  private GhidraScript getGhidraScript(String scriptName) throws Exception {
    ResourceFile scriptSourceFile = findScriptSourceFile(scriptName);
    GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSourceFile);

    if (provider == null) {
      throw new IOException(
          "Missing plugin needed to run scripts of this type. Please "
              + "ensure you have installed the necessary plugin.");
    }

    PrintWriter writer = new PrintWriter(System.out);
    GhidraScript foundScript = provider.getScriptInstance(scriptSourceFile, writer);

    return foundScript;
  }

  /**
   * Find a ResourceFile corresponding to a given script file
   *
   * @param scriptName Script file to locate
   * @return Corresponding ResourceFile to load
   */
  private ResourceFile findScriptSourceFile(String scriptName) {
    ResourceFile scriptSource = new ResourceFile(scriptName);
    scriptSource = scriptSource.getCanonicalFile();
    if (scriptSource.exists()) {
      return scriptSource;
    }

    List<String> scriptPaths = null;
    GhidraScriptUtil.initialize(new BundleHost(), scriptPaths);
    scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
    if (scriptSource != null) {
      return scriptSource;
    }
    throw new IllegalArgumentException("Script not found: " + scriptName);
  }

  /**
   * Run the Retypd.java script file on a given (project, program) pair
   *
   * @param project Project that owns the program
   * @param program Program to run the project file on
   */
  private void runRetypdScript(Project project, Program program) throws Exception {
    GhidraState state = new GhidraState(null, project, program, null, null, null);
    PrintWriter writer = new PrintWriter(System.out);

    try {
      GhidraScript retypdScript = getGhidraScript("Retypd.java");
      retypdScript.execute(state, TaskMonitor.DUMMY, writer);
    } finally {
      GhidraScriptUtil.dispose();
    }
  }

  @Test
  public void testRetypdExecutes() throws Exception {
    Project project = openProject(TEST_DIR, "test-project");

    try {
      Program program = getProgram(project, "test-structs-hf", this);
      runRetypdScript(project, program);
    } finally {
      project.close();
    }
  }

  private static Map<String, String> prototypeMap;

  static {
    prototypeMap = new HashMap<String, String>();
    prototypeMap.put("foo1", "undefined foo1(float param_1, struct_2 * param_2)");
    prototypeMap.put("foo2", "undefined foo2(float param_1, float param_2, struct_1 * param_3)");
    prototypeMap.put("foo3", "void foo3(float param_1, struct_0 * param_2)");
  }

  @Test
  public void testRetypdTypesCorrectly() throws Exception {
    Project project = openProject(TEST_DIR, "test-project");

    try {
      Program program = getProgram(project, "test-structs-hf", this);
      runRetypdScript(project, program);

      FunctionManager funcMgr = program.getFunctionManager();

      for (Function func : funcMgr.getFunctions(true)) {
        if (prototypeMap.containsKey(func.getName())) {
          String expected = prototypeMap.get(func.getName());
          assertEquals(expected, func.getPrototypeString(true, false));
        }
      }
    } finally {
      project.close();
    }
  }
}
