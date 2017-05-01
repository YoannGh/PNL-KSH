CC       = gcc
# compiling flags here
CFLAGS   = -Wall -Wextra -std=c99

LINKER   = gcc
# linking flags here
LFLAGS   = 

# change these to proper directories where each file should be
SRCDIR   = src
INCDIR   = module
OBJDIR   = obj
BINDIR   = bin

BIN_NAME = ksh-tool

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(INCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
RM        = rm -rf
MKDIR_P   = mkdir -p

all: out_directories module tool

.PHONY: module
module: 
	make -C module

.PHONY: tool
tool: out_directories $(BINDIR)/$(BIN_NAME)

$(BINDIR)/$(BIN_NAME): $(OBJECTS)
	$(LINKER) $(LFLAGS) -o $@ $^

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

.PHONY: out_directories
out_directories:
	$(MKDIR_P) $(OBJDIR) $(BINDIR)

.PHONY: clean
clean:
	$(RM) $(OBJDIR)
	make -C module clean

.PHONY: remove
remove: clean
	$(RM) $(BINDIR)
	
