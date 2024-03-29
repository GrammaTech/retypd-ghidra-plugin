#!/bin/bash
set -x

mkdir -p third-party


# Installs gradle, which is needed for extensions
GRADLE=gradle-7.3-bin.zip

# Get gradle from u4
wget -nv https://services.gradle.org/distributions/$GRADLE

# Put it in /third-party
unzip $GRADLE -d third-party

# Rename so we don't have to parse version names
pushd `pwd`/third-party
ln -s gradle-* gradle
popd

rm $GRADLE

# Build ghidra from GrammaTech fork
# Ghidra_10.2.2 seems to give problems when decompiling with ifc.toggleParamMeasures(true);
git clone https://github.com/GrammaTech/ghidra.git ghidra_build
#git clone https://github.com/NationalSecurityAgency/ghidra.git --branch Ghidra_10.2.2_build ghidra_build
pushd ghidra_build

gradle -I gradle/support/fetchDependencies.gradle init
gradle buildGhidra
GHIDRA=$(ls build/dist/)
popd


# Get the version from the ghidra script
IFS='_' read -ra PARSED_FILENAME <<< "$GHIDRA"
VERSION=${PARSED_FILENAME[1]}

unzip ghidra_build/build/dist/$GHIDRA -d third-party
rm -r ghidra_build



# Create some links in /usr/local/bin for convenience
ln -s `pwd`/third-party/ghidra_${VERSION}_DEV/support/analyzeHeadless /usr/local/bin/analyzeHeadless
ln -s `pwd`/third-party/ghidra_${VERSION}_DEV/ghidraRun /usr/local/bin/ghidraRun

# Create a soft link so we don't have to remember the ghidra version
ln -s `pwd`/third-party/ghidra_${VERSION}_DEV `pwd`/third-party/ghidra


# We need the ghidra jar anyway, so lets build it
pushd `pwd`/third-party/ghidra_${VERSION}_DEV/support
./buildGhidraJar
popd


