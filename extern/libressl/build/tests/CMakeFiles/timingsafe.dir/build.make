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
include tests/CMakeFiles/timingsafe.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/timingsafe.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/timingsafe.dir/flags.make

tests/CMakeFiles/timingsafe.dir/timingsafe.c.o: tests/CMakeFiles/timingsafe.dir/flags.make
tests/CMakeFiles/timingsafe.dir/timingsafe.c.o: ../tests/timingsafe.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/timingsafe.dir/timingsafe.c.o"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/timingsafe.dir/timingsafe.c.o   -c /home/jackson/CLionProjects/untitled1/extern/libressl/tests/timingsafe.c

tests/CMakeFiles/timingsafe.dir/timingsafe.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/timingsafe.dir/timingsafe.c.i"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/extern/libressl/tests/timingsafe.c > CMakeFiles/timingsafe.dir/timingsafe.c.i

tests/CMakeFiles/timingsafe.dir/timingsafe.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/timingsafe.dir/timingsafe.c.s"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/extern/libressl/tests/timingsafe.c -o CMakeFiles/timingsafe.dir/timingsafe.c.s

# Object files for target timingsafe
timingsafe_OBJECTS = \
"CMakeFiles/timingsafe.dir/timingsafe.c.o"

# External object files for target timingsafe
timingsafe_EXTERNAL_OBJECTS =

tests/timingsafe: tests/CMakeFiles/timingsafe.dir/timingsafe.c.o
tests/timingsafe: tests/CMakeFiles/timingsafe.dir/build.make
tests/timingsafe: tls/libtls.so.20.1.0
tests/timingsafe: ssl/libssl.so.48.1.0
tests/timingsafe: crypto/libcrypto.so.46.1.0
tests/timingsafe: tests/CMakeFiles/timingsafe.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jackson/CLionProjects/untitled1/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable timingsafe"
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/timingsafe.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/timingsafe.dir/build: tests/timingsafe

.PHONY : tests/CMakeFiles/timingsafe.dir/build

tests/CMakeFiles/timingsafe.dir/clean:
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/timingsafe.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/timingsafe.dir/clean

tests/CMakeFiles/timingsafe.dir/depend:
	cd /home/jackson/CLionProjects/untitled1/extern/libressl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jackson/CLionProjects/untitled1/extern/libressl /home/jackson/CLionProjects/untitled1/extern/libressl/tests /home/jackson/CLionProjects/untitled1/extern/libressl/build /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests /home/jackson/CLionProjects/untitled1/extern/libressl/build/tests/CMakeFiles/timingsafe.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/timingsafe.dir/depend

