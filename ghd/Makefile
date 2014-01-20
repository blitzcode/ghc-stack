
# Compile all C++98 and C99 code

EXECUTABLE_NAME = ghd

# Default target depending on main output
.PHONY : all
all : $(EXECUTABLE_NAME) 

# General compiler and linker flags
FLAGS = -m32 -g -Wall -Wextra -Wno-unused-parameter -O3 -fno-omit-frame-pointer

# Flags specific to C or C++ code
CFLAGS = $(FLAGS) -std=c99 \
	 -I/Library/Frameworks/GHC.framework/Versions/7.6.3-i386/usr/lib/ghc-7.6.3/include/
CXXFLAGS = $(FLAGS) -std=c++98

# Sources and objects. We assume all .c / .cpp files in the directory are meant to
# be compiled
SRC = $(wildcard *.c) $(wildcard *.cpp)
OBJ = $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRC)))

# Rule for producing the main output
LD_OBJ = $(OBJ)
$(EXECUTABLE_NAME) : $(LD_OBJ)
	$(CXX) -o $@ $(FLAGS) $(LDFLAGS) $(LD_OBJ)

# Only include this if we actually build the main output, don't want to
# generate dependencies for the clean targets etc.
ifeq ($(MAKECMDGOALS), )
 
# Automatically generate dependencies with the compiler for each source file
%.d: %.cpp
	@set -e; rm -f $@; \
	 $(CXX) -MM $(CXXFLAGS) $< > $@.$$$$; \
	 sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 $(RM) $@.$$$$
%.d: %.c
	@set -e; rm -f $@; \
	 $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	 sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 $(RM) $@.$$$$

# Include the generated dependencies for object and dependency files. Be silent
# during the first compile where the .d files have not been generated yet and
# everything is recompiled
-include $(patsubst %.cpp,%.d,$(patsubst %.c,%.d,$(SRC)))

endif

# Clean by deleting final output, dependency and object files
.PHONY : clean
clean:
	$(RM) $(EXECUTABLE_NAME) $(OBJ) $(OBJ:.o=.d)

