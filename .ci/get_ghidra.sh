#!/bin/bash
mkdir -p third-party

# Installs ghidra from default sources
GHIDRA=ghidra_10.0.4_PUBLIC_20210928.zip

# Get the version from the ghidra script
IFS='_' read -ra PARSED_FILENAME <<< "$GHIDRA"
VERSION=${PARSED_FILENAME[1]}
# Get Ghidra from u4
wget -nv https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.4_build/$GHIDRA
unzip $GHIDRA -d third-party

# Create some links in /usr/local/bin for convenience
ln -s `pwd`/third-party/ghidra_${VERSION}_DEV/support/analyzeHeadless /usr/local/bin/analyzeHeadless
ln -s `pwd`/third-party/ghidra_${VERSION}_DEV/ghidraRun /usr/local/bin/ghidraRun

# Create a soft link so we don't have to remember the ghidra version
ln -s `pwd`/third-party/ghidra_${VERSION}_DEV `pwd`/third-party/ghidra

# Clean it up
rm $GHIDRA

# We need the ghidra jar anyway, so lets build it
pushd `pwd`/third-party/ghidra_${VERSION}_DEV/support
./buildGhidraJar
popd

# Installs gradle, which is needed for extensions
GRADLE=gradle-7.1.1-bin.zip

# Get gradle from u4
wget -nv https://services.gradle.org/distributions/$GRADLE

# Put it in /third-party
unzip $GRADLE -d third-party

# Rename so we don't have to parse version names
pushd `pwd`/third-party
ln -s gradle-* gradle
popd

rm $GRADLE
