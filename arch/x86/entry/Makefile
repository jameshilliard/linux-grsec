#
# Makefile for the x86 low level entry code
#
obj-y				:= entry_$(BITS).o thunk_$(BITS).o syscall_$(BITS).o
obj-y				+= common.o

obj-y				+= vdso/
obj-y				+= vsyscall/

obj-$(CONFIG_IA32_EMULATION)	+= entry_64_compat.o syscall_32.o

CFLAGS_REMOVE_syscall_32.o = -fplugin-arg-rap_plugin-hash=abs-finish
CFLAGS_REMOVE_syscall_32.o = -fplugin-arg-rap_plugin-hash=abs-ops
CFLAGS_REMOVE_syscall_32.o = -fplugin-arg-rap_plugin-hash=abs-attr
CFLAGS_REMOVE_syscall_64.o = -fplugin-arg-rap_plugin-hash=abs-finish
CFLAGS_REMOVE_syscall_64.o = -fplugin-arg-rap_plugin-hash=abs-ops
CFLAGS_REMOVE_syscall_64.o = -fplugin-arg-rap_plugin-hash=abs-attr

GCC_PLUGINS_syscall_32.o := n
GCC_PLUGINS_syscall_64.o := n
