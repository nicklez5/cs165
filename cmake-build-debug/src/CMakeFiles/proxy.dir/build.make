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
include src/CMakeFiles/proxy.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/proxy.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/proxy.dir/flags.make

src/CMakeFiles/proxy.dir/proxy/proxy.c.o: src/CMakeFiles/proxy.dir/flags.make
src/CMakeFiles/proxy.dir/proxy/proxy.c.o: ../src/proxy/proxy.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/proxy.dir/proxy/proxy.c.o"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/proxy.dir/proxy/proxy.c.o   -c /home/jackson/CLionProjects/untitled1/src/proxy/proxy.c

src/CMakeFiles/proxy.dir/proxy/proxy.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/proxy.dir/proxy/proxy.c.i"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/src/proxy/proxy.c > CMakeFiles/proxy.dir/proxy/proxy.c.i

src/CMakeFiles/proxy.dir/proxy/proxy.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/proxy.dir/proxy/proxy.c.s"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/src/proxy/proxy.c -o CMakeFiles/proxy.dir/proxy/proxy.c.s

src/CMakeFiles/proxy.dir/proxy/bloom.c.o: src/CMakeFiles/proxy.dir/flags.make
src/CMakeFiles/proxy.dir/proxy/bloom.c.o: ../src/proxy/bloom.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/CMakeFiles/proxy.dir/proxy/bloom.c.o"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/proxy.dir/proxy/bloom.c.o   -c /home/jackson/CLionProjects/untitled1/src/proxy/bloom.c

src/CMakeFiles/proxy.dir/proxy/bloom.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/proxy.dir/proxy/bloom.c.i"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/src/proxy/bloom.c > CMakeFiles/proxy.dir/proxy/bloom.c.i

src/CMakeFiles/proxy.dir/proxy/bloom.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/proxy.dir/proxy/bloom.c.s"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/src/proxy/bloom.c -o CMakeFiles/proxy.dir/proxy/bloom.c.s

# Object files for target proxy
proxy_OBJECTS = \
"CMakeFiles/proxy.dir/proxy/proxy.c.o" \
"CMakeFiles/proxy.dir/proxy/bloom.c.o"

# External object files for target proxy
proxy_EXTERNAL_OBJECTS =

src/proxy: src/CMakeFiles/proxy.dir/proxy/proxy.c.o
src/proxy: src/CMakeFiles/proxy.dir/proxy/bloom.c.o
src/proxy: src/CMakeFiles/proxy.dir/build.make
src/proxy: /usr/local/lib/libtls.so
src/proxy: /usr/local/lib/libssl.so
src/proxy: /usr/local/lib/libcrypto.so
src/proxy: src/CMakeFiles/proxy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jackson/CLionProjects/untitled1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable proxy"
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/proxy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/proxy.dir/build: src/proxy

.PHONY : src/CMakeFiles/proxy.dir/build

src/CMakeFiles/proxy.dir/clean:
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug/src && $(CMAKE_COMMAND) -P CMakeFiles/proxy.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/proxy.dir/clean

src/CMakeFiles/proxy.dir/depend:
	cd /home/jackson/CLionProjects/untitled1/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jackson/CLionProjects/untitled1 /home/jackson/CLionProjects/untitled1/src /home/jackson/CLionProjects/untitled1/cmake-build-debug /home/jackson/CLionProjects/untitled1/cmake-build-debug/src /home/jackson/CLionProjects/untitled1/cmake-build-debug/src/CMakeFiles/proxy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/proxy.dir/depend

