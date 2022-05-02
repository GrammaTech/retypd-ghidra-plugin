package ghidraretypd;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParamID;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/** Class for managing the generation of retypd constraints based on high-level PCode */
public class RetypdGenerate {
  private Program program;
  private Map<String, Set<String>> constraints;

  public RetypdGenerate(Program program) {
    this.program = program;
    constraints = new HashMap<String, Set<String>>();
  }

  /**
   * Translate a varnode to a string for constraint generation
   *
   * @param var High-level varnode to translate
   * @return Type variable for use in constraints
   */
  private String varnode(Varnode var) {
    if (!(var instanceof VarnodeAST)) {
      return "";
    }

    VarnodeAST varAST = (VarnodeAST) var;
    return "v_" + varAST.getUniqueId();
  }

  /**
   * Translate a function to a string for constraint generation
   *
   * @param func Function whose name to translate
   * @return Type variable for use in constraints
   */
  private String function(Function func) {
    String name = func.getSymbol().getName();
    return name.replace(".", "_").replace("@", "_");
  }

  /**
   * Translate a function input to a string for constraint generation
   *
   * @param func Function to translate
   * @param num Which number of input to translate
   * @return Type path for use in constraints
   */
  private String functionIn(Function func, int num) {
    return function(func) + ".in_" + num;
  }

  /**
   * Translate a function output to a string for constraint generation
   *
   * @param func Function to translate
   * @return Type path for use in constraints
   */
  private String functionOut(Function func) {
    return function(func) + ".out";
  }

  /**
   * Translate a varnode dereference to a string for constraint generation
   *
   * @param src Varnode which is being dereferenced
   * @param mode `store` or `load` for Pcode STORE/LOAD respectively
   * @param size The byte size of the load or store
   * @param offset The offset into the varnode that is being dereferenced
   * @return Type path for use in constraints
   */
  private String deref(Varnode src, String mode, long size, long offset) {
    return varnode(src) + "." + mode + ".σ" + size + "@" + offset;
  }

  /**
   * Translate a high-level Pcode instruction to a dereference path string
   *
   * @param op Pcode instruction that defines the address being dereferenced
   * @param mode `store` or `load` for Pcode STORE/LOAD respectively
   * @return Type path for use in cosntraints
   */
  private String derefLabel(PcodeOp op, String mode) {
    switch (op.getOpcode()) {
      case PcodeOp.CAST:
        VarnodeAST castArg = (VarnodeAST) op.getInput(0);
        if (castArg.getDef() != null) {
          return derefLabel(castArg.getDef(), mode);
        } else {
          return deref(castArg, mode, op.getOutput().getSize(), 0);
        }
      case PcodeOp.INT_ADD:
      case PcodeOp.PTRSUB:
        return deref(op.getInput(0), mode, op.getOutput().getSize(), op.getInput(1).getOffset());
      case PcodeOp.PTRADD:
        long offset = op.getInput(1).getOffset();
        long size = op.getInput(2).getOffset();
        return deref(op.getInput(0), mode, op.getOutput().getSize(), offset * size);
    }

    return deref(op.getOutput(), mode, op.getOutput().getSize(), 0);
  }

  /**
   * Generate and store constraints for a given function
   *
   * @param func Function to generate constraints for
   * @param ifc Initialized decompiler interface
   */
  private void generateForFunction(Function func, DecompInterface ifc) {
    Program program = func.getProgram();
    FunctionManager funcManager = program.getFunctionManager();
    DecompileResults res = ifc.decompileFunction(func, 300, null);
    HighFunction highFunc = res.getHighFunction();

    // Update parameters if we do not have any
    HighParamID highParams = res.getHighParamID();
    if (highParams != null && func.getParameters().length == 0) {
      highParams.storeParametersToDatabase(true, SourceType.ANALYSIS);
      highParams.storeReturnToDatabase(true, SourceType.ANALYSIS);
    }

    Set<String> funcConstraints = new HashSet<String>();
    Map<String, Integer> params = new HashMap<String, Integer>();

    // Load parameters, and if it has a user defined type, apply it
    for (Parameter param : func.getParameters()) {
      params.put(param.getName(), param.getOrdinal());

      if (func.getSignatureSource() == SourceType.USER_DEFINED) {
        int num = param.getOrdinal();
        funcConstraints.add(functionIn(func, num) + " ⊑ " + param.getDataType().toString());
      }
    }

    if (func.getSignatureSource() == SourceType.USER_DEFINED) {
      funcConstraints.add(func.getReturnType() + " ⊑ " + functionOut(func));
    }

    for (PcodeBlockBasic block : highFunc.getBasicBlocks()) {
      for (Iterator<PcodeOp> pcode_it = block.getIterator(); pcode_it.hasNext(); ) {
        PcodeOp pcode = pcode_it.next();

        // Handle inputs in the arguments
        for (Varnode var : pcode.getInputs()) {
          assert (var instanceof VarnodeAST);
          VarnodeAST varAST = (VarnodeAST) var;
          HighVariable highVar = varAST.getHigh();

          if (varAST.getDef() != null
              || highVar == null
              || varAST.isConstant()
              || varAST.isAddress()) {
            continue;
          }

          if (params.containsKey(highVar.getName())) {
            int slot = params.get(highVar.getName());
            funcConstraints.add(functionIn(func, slot) + " ⊑ " + varnode(var));
          }
        }

        // Handle specific opcodes
        switch (pcode.getOpcode()) {
          case PcodeOp.FLOAT_ADD:
          case PcodeOp.FLOAT_SUB:
          case PcodeOp.FLOAT_MULT:
          case PcodeOp.FLOAT_DIV:
          case PcodeOp.FLOAT_NEG:
          case PcodeOp.FLOAT_SQRT:
            for (Varnode var : pcode.getInputs()) {
              String type = var.getSize() == 8 ? "double" : "float";
              funcConstraints.add(varnode(var) + " ⊑ " + type);
              funcConstraints.add(varnode(var) + " ⊑ " + varnode(pcode.getOutput()));
            }
            break;
          case PcodeOp.RETURN:
            if (pcode.getNumInputs() == 2) {
              funcConstraints.add(varnode(pcode.getInput(1)) + " ⊑ " + functionOut(func));
            }
            break;
          case PcodeOp.COPY:
          case PcodeOp.INDIRECT:
          case PcodeOp.CAST:
            funcConstraints.add(varnode(pcode.getInput(0)) + " ⊑ " + varnode(pcode.getOutput()));
            break;
          case PcodeOp.CALL:
            Varnode addr = pcode.getInput(0);
            if (addr.isAddress()) {
              Function called = funcManager.getFunctionContaining(addr.getAddress());

              if (called != null) {
                for (int i = 1; i < pcode.getNumInputs(); i++) {
                  VarnodeAST input = (VarnodeAST) pcode.getInput(i);

                  if (input.getDef() == null) {
                    continue;
                  }

                  funcConstraints.add(varnode(input) + " ⊑ " + functionIn(called, i - 1));
                }

                if (pcode.getOutput() != null) {
                  funcConstraints.add(functionOut(called) + " ⊑ " + varnode(pcode.getOutput()));
                }
              }
            }
            break;
          case PcodeOp.STORE:
            Varnode var = pcode.getInput(1);
            VarnodeAST varAST = (VarnodeAST) var;
            String dest;
            if (varAST.getDef() != null) {
              dest = derefLabel(varAST.getDef(), "store");
            } else {
              dest = deref(varAST, "store", var.getSize(), 0);
            }
            funcConstraints.add(varnode(pcode.getInput(2)) + " ⊑ " + dest);
            break;
          case PcodeOp.LOAD:
            var = pcode.getInput(1);
            varAST = (VarnodeAST) var;
            String src;
            if (varAST.getDef() != null) {
              src = derefLabel(varAST.getDef(), "load");
            } else {
              src = deref(varAST, "load", var.getSize(), 0);
            }
            funcConstraints.add(src + " ⊑ " + varnode(pcode.getOutput()));
            break;
        }
      }
    }

    constraints.put(func.getName(), funcConstraints);
  }

  /**
   * Generate and store constraints for the currently loaded program
   *
   * @throws DecompileException Thrown on failure to decompile a function
   */
  private void generateForProgram() throws DecompileException {
    DecompileOptions options = new DecompileOptions();
    DecompInterface ifc = new DecompInterface();
    ifc.setOptions(options);
    ifc.toggleParamMeasures(true);

    if (!ifc.openProgram(program)) {
      throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
    }

    for (Function func : program.getFunctionManager().getFunctions(false)) {
      generateForFunction(func, ifc);
    }
  }

  /**
   * Create a callgraph (map of function to the set of functions that that function calls) using
   * strings that correspond to the functions names formatted as they would appear in constraints
   *
   * @return The generated mapping
   */
  private Map<String, Set<String>> calculateCallgraph() {
    Map<String, Set<String>> callgraph = new HashMap<String, Set<String>>();

    for (Function func : program.getFunctionManager().getFunctions(false)) {
      Set<String> found = new HashSet<String>();
      for (Function callee : func.getCalledFunctions(TaskMonitor.DUMMY)) {
        found.add(function(callee));
      }
      callgraph.put(function(func), found);
    }

    return callgraph;
  }

  /**
   * Create a mapping of strings that correspond ot function names formatted as they would appear in
   * constraints to their original name such that they can be mapped to their original function in
   * Ghidra
   *
   * @return The generated mapping
   */
  private Map<String, String> calculateNameMap() {
    Map<String, String> nameMap = new HashMap<String, String>();

    for (Function func : program.getFunctionManager().getFunctions(false)) {
      nameMap.put(function(func), func.getName());
    }

    return nameMap;
  }

  /** Results class used for generating the JSON file */
  class RetypdResults {
    private String language;
    private Map<String, Set<String>> constraints;
    private Map<String, Set<String>> callgraph;
    private Map<String, String> nameMap;

    public RetypdResults(
        Language language,
        Map<String, Set<String>> constraints,
        Map<String, Set<String>> callgraph,
        Map<String, String> nameMap) {
      this.language = language.toString();
      this.constraints = constraints;
      this.callgraph = callgraph;
      this.nameMap = nameMap;
    }
  }

  /**
   * Generate a JSON file containing the associated constraint information
   *
   * @return String containing prettified JSON
   * @throws DecompileException Thrown on failure to decompile a function
   */
  public String getJSON() throws DecompileException {
    if (constraints.isEmpty()) {
      generateForProgram();
    }

    Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
    RetypdResults res =
        new RetypdResults(
            program.getLanguage(), constraints, calculateCallgraph(), calculateNameMap());
    return gson.toJson(res);
  }
}
