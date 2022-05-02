# retypd-ghidra-plugin

This project implements a [Ghidra](https://ghidra-sre.org/) plugin that exposes
a script which implements type inference utilizing the [Retypd](https://github.com/GrammaTech/retypd) algorithm.

## Structure

This plugin involves two components:

- `GhidraRetypd` which is a plugin for Ghidra which generates Retypd type
  constraints based on the high-level Pcode of the functions for a given
  Program and writes this in a JSON serialization. After type inference is run
  on this, the output of the inference is then used to update the type
  information in Ghidra.
- `ghidra_retypd_provider` is a Python package which reads the JSON serialized
  type constraints, runs the `retypd` package on those constraints, and writes
  back to disk a JSON serialization of the output types.

# Installation

First, the `GhidraRetypd` package can be installed using the Makefile at the
root of this repository. First, make sure the `GHIDRA_INSTALL_DIR` environment
variable points to the root of your Ghidra installation. Then, use
`make install` to compile and install the Ghidra extension. For the python
package, create a virtual environment with `python3.8 -m venv venv`, and install
the package with `python3.8 -m pip install .`.

# Usage

Make sure prior to launching your virtual environment created above is active,
with `source ./venv/bin/activate`. Then, in the same terminal, you can launch
Ghidra by invoking `$GHIDRA_INSTALL_DIR/ghidraRun`. Once launched, and a
program loaded for analysis is ready, go to the Script Manager (either by
going to `Window -> Script Manager` or by using the ![Play Button](https://git.grammatech.com/reverse-engineering/remath/ghidra/-/raw/72a8bac6d20c9b44ca56578ec3239088fee9c699/GhidraDocs/images/play.png)
button in the tool bar). Then search for `Retypd.java`, and double click to run
the script. Once the script has finihsed running, the types will be applied to
the current program.
