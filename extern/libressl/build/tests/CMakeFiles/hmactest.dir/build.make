# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/jackson/CLionProjects/untitled1/extern/cmake/bin/cmake

# The command to remove a file.
RM = /home/jackson/CLionProjects/untitled1/extern/cmake/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jackson/CLionProjects/untitled1/extern/libressl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jackson/CLionProjects/untitled1/extern/libressl/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/hmactest.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/hmactest.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/hmactest.dir/flags.make

tests/CMakeFiles/hmactest.dir/hmactest.c.o: tests/CMakeFiles/hmactest.dir/flags.make
tests/CMakeFiles/hmactest.dir/hmactest.c.o: ../tests/hmactest.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/hmactest.dir/hmactest.c.o"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hmactest.dir/hmactest.c.o   -c /home/jackson/CLionProjects/untitled1/extern/libressl/tests/hmactest.c

tests/CMakeFiles/hmactest.dir/hmactest.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hmactest.dir/hmactest.c.i"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/extern/libressl/tests/hmactest.c > CMakeFiles/hmactest.dir/hmactest.c.i

tests/CMakeFiles/hmactest.dir/hmactest.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hmactest.dir/hmactest.c.s"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/extern/libressl/tests/hmactest.c -o CMakeFiles/hmactest.dir/hmactest.c.s

# Object files for target hmactest
hmactest_OBJECTS = \
"CMakeFiles/hmactest.dir/hmactest.c.o"

# External object files for target hmactest
hmactest_EXTERNAL_OBJECTS =

tests/hmactest: tests/CMakeFiles/hmactest.dir/hmactest.c.o
tests/hmactest: tests/CMakeFiles/hmactest.dir/build.make
tests/hmactest: tls/libtls.so.20.1.0
tests/hmactest: ssl/libssl.so.48.1.0
tests/hmactest: crypto/libcrypto.so.46.1.0
tests/hmactest: tests/CMakeFiles/hmactest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jackson/CLionProjects/untitled1/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable hmactest"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hmactest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/hmactest.dir/build: tests/hmactest

.PHONY : tests/CMakeFiles/hmactest.dir/build

tests/CMakeFiles/hmactest.dir/clean:
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/hmactest.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/hmactest.dir/clean

tests/CMakeFiles/hmactest.dir/depend:
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jackson/CLionProjects/untitled1/extern/libressl /home/jackson/CLionProjects/untitled1/extern/libressl/tests /home/jackson/CLionProjects/untitled1/extern/libressl/build /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests/CMakeFiles/hmactest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/hmactest.dir/depend

