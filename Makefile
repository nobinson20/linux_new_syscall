# DO NOT TOUCH THIS
ifeq ($(platform), emulator)
	CC := $(HOME)/./Android/Sdk/ndk/20.0.5594570/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android29-clang
endif

# NOTE:
#   Use $(CC) instead of compiler name (e.g. gcc, clang).
#   Since your user-space program is simple, $(CC) is able to handle
#   everything. Do not use other executables for compiling/linking.

# ---------- Write the rest of Makefile below ----------

default:
	$(CC) test_new_syscall.c -o test

.PHONY: clean
clean:
	rm -f *.o test
