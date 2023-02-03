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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParamID;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/** Class for managing the generation of retypd constraints based on high-level PCode */
public class RetypdGenerate {
  private Program program;

  public RetypdGenerate(Program program) {
    this.program = program;
  }

  /**
   * Translate a varnode to a string for constraint generation
   *
   * @param var High-level varnode to translate
   * @return Type variable for use in constraints
   */
  private static String varnode(Varnode var) {
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
  public static String fmtFunctionName(Function func) {
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
  private static String functionIn(Function func, int num) {
    return fmtFunctionName(func) + ".in_" + num;
  }

  /**
   * Translate a varnode function input to a string for constraint generation
   *
   * @param var Varnode to translate
   * @param num Which number of input to translate
   * @return Type path for use in constraints
   */
  private static String varIn(Varnode var, int num) {
    return varnode(var) + ".in_" + num;
  }

  /**
   * Translate a function output to a string for constraint generation
   *
   * @param func Function to translate
   * @return Type path for use in constraints
   */
  private static String functionOut(Function func) {
    return fmtFunctionName(func) + ".out";
  }

  /**
   * Translate a function output to a string for constraint generation
   *
   * @param var Varnode to translate
   * @return Type path for use in constraints
   */
  private static String varOut(Varnode var) {
    return varnode(var) + ".out";
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
  private static String deref(Varnode src, String mode, long size, int offset) {
    String offsetStr;

    switch (offset) {
      case -1:
        offsetStr = "0*[nobound]";
        break;
      case -2:
        offsetStr = "0*[nullterm]";
        break;
      default:
        offsetStr = offset + "";
        break;
    }

    return varnode(src) + "." + mode + ".σ" + size + "@" + offsetStr;
  }

  /**
   * Translate a high-level Pcode instruction to a dereference path string
   *
   * @param orig Varnode of the address being dereferenced
   * @param mode `store` or `load` for Pcode STORE/LOAD respectively
   * @return Type path for use in constraints
   */
  private String derefLabel(Varnode orig, int size, String mode) {
    PcodeOp op = orig.getDef();

    if (op == null) {
      return deref(orig, mode, size, 0);
    }

    switch (op.getOpcode()) {
      case PcodeOp.CAST:
        VarnodeAST castArg = (VarnodeAST) op.getInput(0);
        if (castArg.getDef() != null) {
          return derefLabel(castArg, size, mode);
        } else {
          return deref(castArg, mode, size, 0);
        }
      case PcodeOp.INT_ADD:
        if (op.getInput(0).isConstant() && !op.getInput(1).isConstant()) {
          // Swap the arguments
          Varnode lhs = op.getInput(0);
          Varnode rhs = op.getInput(1);
          op.setInput(lhs, 1);
          op.setInput(rhs, 0);
        }
        // Fallthrough
      case PcodeOp.PTRSUB:
        if (op.getInput(1).isConstant() && !op.getInput(1).isAddress()) {
          int offset = (int) op.getInput(1).getOffset();
          if (offset >= 0) {
            return deref(op.getInput(0), mode, size, offset);
          }
        } else {
          return deref(op.getInput(0), mode, size, -1);
        }
        break;
      case PcodeOp.PTRADD:
        if (op.getInput(1).isConstant()
            && !op.getInput(1).isAddress()
            && op.getInput(2).isConstant()) {
          int offset = (int) op.getInput(1).getOffset();
          int strideSize = (int) op.getInput(2).getOffset();
          if (offset * strideSize >= 0) {
            return deref(op.getInput(0), mode, size, offset * strideSize);
          }
        }
        break;
    }

    return deref(op.getOutput(), mode, size, 0);
  }

  private static Map<String, Map<Integer, String>> typeSize;

  static {
    typeSize = new HashMap<String, Map<Integer, String>>();
    typeSize.put("bool", new HashMap<Integer, String>());
    typeSize.put("int", new HashMap<Integer, String>());
    typeSize.put("uint", new HashMap<Integer, String>());
    typeSize.put("float", new HashMap<Integer, String>());

    typeSize.get("bool").put(1, "bool");
    typeSize.get("bool").put(4, "bool");
    typeSize.get("bool").put(8, "bool");

    typeSize.get("float").put(4, "float");
    typeSize.get("float").put(8, "double");

    typeSize.get("int").put(1, "int8");
    typeSize.get("int").put(2, "int16");
    typeSize.get("int").put(4, "int32");
    typeSize.get("int").put(8, "int64");

    typeSize.get("uint").put(1, "uint8");
    typeSize.get("uint").put(2, "uint16");
    typeSize.get("uint").put(4, "uint32");
    typeSize.get("uint").put(8, "uint64");
  }

  static class PcodeOpType {
    public String output;
    public String[] inputs;

    public PcodeOpType(String output, String... inputs) {
      this.output = output;
      this.inputs = inputs;
    }

    public void addConstraints(PcodeOp op, Set<String> constraints) {
      if (output != null) {
        String type = typeSize.get(output).get(op.getOutput().getSize());
        constraints.add(type + " ⊑ " + varnode(op.getOutput()));
      }

      assert (inputs.length == op.getNumInputs());

      for (int i = 0; i < inputs.length; i++) {
        Varnode var = op.getInput(i);
        String type = typeSize.get(inputs[i]).get(var.getSize());
        constraints.add(varnode(var) + " ⊑ " + type);
      }
    }
  }

  private static Map<Integer, PcodeOpType> opTypes;

  static {
    opTypes = new HashMap<Integer, PcodeOpType>();
    // opTypes.put(PcodeOp.INT_EQUAL, new PcodeOpType("bool", "int", "int"));
    // opTypes.put(PcodeOp.INT_NOTEQUAL, new PcodeOpType("bool", "int", "int"));
    opTypes.put(PcodeOp.INT_SLESS, new PcodeOpType("bool", "int", "int"));
    opTypes.put(PcodeOp.INT_SLESSEQUAL, new PcodeOpType("bool", "int", "int"));
    opTypes.put(PcodeOp.INT_LESS, new PcodeOpType("bool", "uint", "uint"));
    opTypes.put(PcodeOp.INT_LESSEQUAL, new PcodeOpType("bool", "uint", "uint"));
    opTypes.put(PcodeOp.INT_ZEXT, new PcodeOpType("uint", "int"));
    opTypes.put(PcodeOp.INT_SEXT, new PcodeOpType("int", "int"));
    opTypes.put(PcodeOp.INT_ADD, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_SUB, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_CARRY, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_SCARRY, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_SBORROW, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_2COMP, new PcodeOpType("uint", "uint"));
    opTypes.put(PcodeOp.INT_NEGATE, new PcodeOpType("uint", "uint"));
    opTypes.put(PcodeOp.INT_XOR, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_AND, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_OR, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_LEFT, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_RIGHT, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_SRIGHT, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_MULT, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_DIV, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_SDIV, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.INT_REM, new PcodeOpType("uint", "uint", "uint"));
    opTypes.put(PcodeOp.INT_SREM, new PcodeOpType("int", "int", "int"));
    opTypes.put(PcodeOp.BOOL_NEGATE, new PcodeOpType("bool", "bool"));
    opTypes.put(PcodeOp.BOOL_XOR, new PcodeOpType("bool", "bool", "bool"));
    opTypes.put(PcodeOp.BOOL_AND, new PcodeOpType("bool", "bool", "bool"));
    opTypes.put(PcodeOp.BOOL_OR, new PcodeOpType("bool", "bool", "bool"));
    opTypes.put(PcodeOp.FLOAT_EQUAL, new PcodeOpType("bool", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_NOTEQUAL, new PcodeOpType("bool", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_LESS, new PcodeOpType("bool", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_LESSEQUAL, new PcodeOpType("bool", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_NAN, new PcodeOpType("float"));
    opTypes.put(PcodeOp.FLOAT_ADD, new PcodeOpType("float", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_DIV, new PcodeOpType("float", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_MULT, new PcodeOpType("float", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_SUB, new PcodeOpType("float", "float", "float"));
    opTypes.put(PcodeOp.FLOAT_NEG, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_ABS, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_SQRT, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_INT2FLOAT, new PcodeOpType("int", "float"));
    opTypes.put(PcodeOp.FLOAT_FLOAT2FLOAT, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_TRUNC, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_CEIL, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_FLOOR, new PcodeOpType("float", "float"));
    opTypes.put(PcodeOp.FLOAT_ROUND, new PcodeOpType("float", "float"));
  }

  private void applyDecompilerPrototype(Function func, DecompInterface ifc) {

    if (func.getParameters().length > 0) {
      if (func.getParameter(0).isAutoParameter()) {
        Msg.info(this, "Auto param: " + func.getParameter(0).getFirstStorageVarnode());
      }
      return;
    }

    Program program = func.getProgram();
    FunctionManager funcManager = program.getFunctionManager();
    DecompileResults res = ifc.decompileFunction(func, 300, null);
    HighFunction highFunc = res.getHighFunction();

    if (highFunc == null) {
      Msg.warn(this, "Function " + func.getName() + " has no decompilation");
      return;
    }

    // Update parameters if we do not have any
    HighParamID highParams = res.getHighParamID();

    if (highParams != null) {
      Msg.info(this, "Applied " + highParams.getNumInputs() + " parameters to " + func);
      highParams.storeParametersToDatabase(true, SourceType.ANALYSIS);
      highParams.storeReturnToDatabase(true, SourceType.ANALYSIS);
    }
  }

  /**
   * Generate constraints for a given function
   *
   * @param func Function to generate constraints for
   * @param ifc Initialized decompiler interface
   * @return Set of constraints generated for a function
   */
  private Set<String> generateForFunction(Function func, DecompInterface ifc) {
    Set<String> funcConstraints = new HashSet<String>();
    Program program = func.getProgram();
    FunctionManager funcManager = program.getFunctionManager();
    DecompileResults res = ifc.decompileFunction(func, 300, null);
    HighFunction highFunc = res.getHighFunction();

    if (highFunc == null) {
      Msg.warn(this, "Function " + func.getName() + " has no decompilation");
      return funcConstraints;
    }

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

          // Reason about string constants
          if (highVar != null && highVar instanceof HighConstant) {
            HighConstant highConst = (HighConstant) highVar;
            DataType highConstDt = highConst.getDataType();

            if (highConstDt.toString().equals("char *")) {
              funcConstraints.add(deref(var, "load", 1, -2) + " ⊑ int");
              funcConstraints.add("int ⊑ " + deref(var, "store", 1, -2));
            }
          }

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
          case PcodeOp.RETURN:
            if (pcode.getNumInputs() == 2) {
              funcConstraints.add(varnode(pcode.getInput(1)) + " ⊑ " + functionOut(func));
            }
            break;
          case PcodeOp.INT_EQUAL:
          case PcodeOp.INT_NOTEQUAL:
            funcConstraints.add(varnode(pcode.getInput(0)) + " ⊑ " + varnode(pcode.getInput(1)));
            funcConstraints.add("bool ⊑ " + varnode(pcode.getOutput()));
            break;
          case PcodeOp.COPY:
          case PcodeOp.INDIRECT:
          case PcodeOp.CAST:
            funcConstraints.add(varnode(pcode.getInput(0)) + " ⊑ " + varnode(pcode.getOutput()));
            break;
          case PcodeOp.MULTIEQUAL:
            for (int i = 0; i < pcode.getNumInputs(); i++) {
              funcConstraints.add(varnode(pcode.getInput(i)) + " ⊑ " + varnode(pcode.getOutput()));
            }
            break;
          case PcodeOp.CALLIND:
          case PcodeOp.CALL:
            Varnode addr = pcode.getInput(0);
            Function called = null;
            if (addr.isAddress()) {
              called = funcManager.getFunctionContaining(addr.getAddress());
            }

            for (int i = 1; i < pcode.getNumInputs(); i++) {
              VarnodeAST input = (VarnodeAST) pcode.getInput(i);

              if (input.getDef() == null) {
                continue;
              }

              if (called != null) {
                funcConstraints.add(varnode(input) + " ⊑ " + functionIn(called, i - 1));
              } else {
                funcConstraints.add(varnode(input) + " ⊑ " + varIn(addr, i - 1));
              }
            }

            if (pcode.getOutput() != null) {
              if (called != null) {
                funcConstraints.add(functionOut(called) + " ⊑ " + varnode(pcode.getOutput()));
              } else {
                funcConstraints.add(varOut(addr) + " ⊑ " + varnode(pcode.getOutput()));
              }
            }
            break;
          case PcodeOp.STORE:
            Varnode var = pcode.getInput(1);
            int derefSize = pcode.getInput(2).getSize();
            String dest = derefLabel(var, derefSize, "store");
            funcConstraints.add(varnode(pcode.getInput(2)) + " ⊑ " + dest);
            break;
          case PcodeOp.LOAD:
            var = pcode.getInput(1);
            derefSize = pcode.getOutput().getSize();
            String src = derefLabel(var, derefSize, "load");
            funcConstraints.add(src + " ⊑ " + varnode(pcode.getOutput()));
            break;
          default:
            if (opTypes.containsKey(pcode.getOpcode())) {
              opTypes.get(pcode.getOpcode()).addConstraints(pcode, funcConstraints);
            }
        }
      }
    }

    return funcConstraints;
  }

  /**
   * Generate and store constraints for the currently loaded program
   *
   * @return Map of function name to set of generated constraints for that
   * @throws DecompileException Thrown on failure to decompile a function
   */
  private Map<String, Set<String>> generateForProgram() throws DecompileException {
    DecompileOptions options = new DecompileOptions();
    DecompInterface ifc = new DecompInterface();
    ifc.setOptions(options);
    ifc.toggleParamMeasures(true);

    if (!ifc.openProgram(program)) {
      throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
    }

    Map<String, Set<String>> constraints = new HashMap<String, Set<String>>();

    for (Function func : program.getFunctionManager().getFunctions(false)) {
      applyDecompilerPrototype(func, ifc);
    }

    for (Function func : program.getFunctionManager().getFunctions(false)) {
      Set<String> funcConstraints = generateForFunction(func, ifc);
      constraints.put(fmtFunctionName(func), funcConstraints);
    }

    return constraints;
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
        found.add(fmtFunctionName(callee));
      }
      callgraph.put(fmtFunctionName(func), found);
    }

    return callgraph;
  }

  /** Results class used for generating the JSON file */
  class RetypdResults {
    private String language;
    private Map<String, Set<String>> constraints;
    private Map<String, Set<String>> callgraph;

    public RetypdResults(
        Language language,
        Map<String, Set<String>> constraints,
        Map<String, Set<String>> callgraph) {
      this.language = language.toString();
      this.constraints = constraints;
      this.callgraph = callgraph;
    }
  }

  /**
   * Generate a JSON file containing the associated constraint information
   *
   * @return String containing prettified JSON
   * @throws DecompileException Thrown on failure to decompile a function
   */
  public String getJSON() throws DecompileException {
    Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
    RetypdResults res =
        new RetypdResults(program.getLanguage(), generateForProgram(), calculateCallgraph());

    return gson.toJson(res);
  }
}
