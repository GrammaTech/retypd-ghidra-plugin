EXTENSION_DIR = $(GHIDRA_INSTALL_DIR)/Ghidra/Extensions/
SOURCEDIR = GhidraRetypd/src/main/java/ghidraretypd
JAVA_FILES = $(shell find $(SOURCEDIR) -name "*.java" -print)

all: GhidraRetypd.zip

GhidraRetypd/build/libs/GhidraRetypd.jar: $(JAVA_FILES)
	cd GhidraRetypd && gradle build -x test

GhidraRetypd/lib/GhidraRetypd.jar: GhidraRetypd/build/libs/GhidraRetypd.jar
	mkdir -p GhidraRetypd/lib && cp GhidraRetypd/build/libs/GhidraRetypd.jar GhidraRetypd/lib/GhidraRetypd.jar


GhidraRetypd.zip: GhidraRetypd/lib/GhidraRetypd.jar $(wildcard GhidraRetypd/ghidra_script/*.java) GhidraRetypd/extension.properties GhidraRetypd/build.gradle
	zip -r GhidraRetypd.zip GhidraRetypd

install: GhidraRetypd.zip
	mkdir -p $(EXTENSION_DIR) && unzip -uo GhidraRetypd.zip -d $(EXTENSION_DIR)

clean:
	rm -rf GhidraRetypd.zip GhidraRetypd/build

run: install
	$(GHIDRA_INSTALL_DIR)/ghidraDebug
