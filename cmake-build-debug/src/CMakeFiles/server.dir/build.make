# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


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
CMAKE_COMMAND = /home/jackson/Downloads/clion-2020.1.1/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/jackson/Downloads/clion-2020.1.1/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jackson/CLionProjects/untitled1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jackson/CLionProjects/untitled1/cmake-build-debug

# Include any dependencies generated for this target.
include src/CMakeFiles/server.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/server.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/server.dir/flags.make

src/CMakeFiles/server.dir/server/server.c.o: src/CMakeFiles/server.dir/flags.make
src/CMakeFiles/server.dir/server/server.c.o: ../src/server/server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/server.dir/server/server.c.o"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/server.dir/server/server.c.o   -c /home/jackson/CLionProjects/untitled1/src/server/server.c

src/CMakeFiles/server.dir/server/server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/server.dir/server/server.c.i"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/src/server/server.c > CMakeFiles/server.dir/server/server.c.i

src/CMakeFiles/server.dir/server/server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/server.dir/server/server.c.s"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/src/server/server.c -o CMakeFiles/server.dir/server/server.c.s

# Object files for target server
server_OBJECTS = \
"CMakeFiles/server.dir/server/server.c.o"

# External object files for target server
server_EXTERNAL_OBJECTS =

src/server: src/CMakeFiles/server.dir/server/server.c.o
src/server: src/CMakeFiles/server.dir/build.make
src/server: /usr/local/lib/libtls.so
src/server: /usr/local/lib/libssl.so
src/server: /usr/local/lib/libcrypto.so
src/server: src/CMakeFiles/server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jackson/CLionProjects/untitled1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable server"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/server.dir/build: src/server

.PHONY : src/CMakeFiles/server.dir/build

src/CMakeFiles/server.dir/clean:
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && $(CMAKE_COMMAND) -P CMakeFiles/server.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/server.dir/clean

src/CMakeFiles/server.dir/depend:
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jackson/CLionProjects/untitled1 /home/jackson/CLionProjects/untitled1/src /home/jackson/CLionProjects/untitled1/cmake-build-debug /home/jackson/CLionProjects/untitled1/cmake-build-debug/src /home/jackson/CLionProjects/untitled1/cmake-build-debug/src/CMakeFiles/server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/server.dir/depend

