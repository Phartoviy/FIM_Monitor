CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pedantic

SRC = src/main.cpp \
      src/config_manager.cpp \
      src/file_scanner.cpp \
      src/hash_engine.cpp \
      src/baseline_storage.cpp \
      src/integrity_analyzer.cpp \
      src/threat_classifier.cpp \
      src/report_generator.cpp \
      src/utils.cpp \
      src/logger.cpp \
      src/inotify_monitor.cpp

INC = -Iinclude
OUT = integrity_monitor

all:
	$(CXX) $(CXXFLAGS) $(SRC) $(INC) -o $(OUT)

clean:
	rm -f $(OUT)
