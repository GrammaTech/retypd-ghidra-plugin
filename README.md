# retypd-ghidra-plugin

This project implements a [Ghidra](https://ghidra-sre.org/) plugin that
integrates the [Retypd](https://github.com/GrammaTech/retypd) type analysis.

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

## Docker Install

The quickest way to get started with the `retypd-ghidra-plugin` is to use the
docker container available. This can be built from the root directory of the
repository with:

```bash
docker build -t retypd-image --target interactive -f ./.ci/Dockerfile .
```

and run with:

```bash
xhost +si:localuser:root
docker run -it --privileged \
    --network=host \
    -e DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix:ro \
    retypd-image \
    bash
```

## Manual Install

The retypd ghidra plugin can also be installed outside of a Dockerfile.
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
going to `Window -> Script Manager` or by using the ![Play Button](https://github.com/GrammaTech/ghidra/blob/master/GhidraDocs/images/play.png?raw=true)
button in the tool bar). Then search for `Retypd.java`, and double click to run
the script. Once the script has finished running, the types will be applied to
the current program.
