$(HOSTLIBS)-$(CONFIG_PAX_RAP_PLUGIN) += rap_plugin.so
always := $($(HOSTLIBS)-y)

rap_plugin-objs := $(patsubst $(srctree)/$(src)/%.c,%.o,$(wildcard $(srctree)/$(src)/*.c))

out := ../../../arch/$(SRCARCH)/include/generated/asm
$(objtree)/$(obj)/$(out)/rap.s: $(srctree)/$(src)/rap.S $(srctree)/arch/$(SRCARCH)/include/asm/nospec-branch.h $(srctree)/arch/$(SRCARCH)/include/asm/alternative-asm.h FORCE
	$(Q)mkdir -p $(objtree)/$(obj)/$(out)
	$(call if_changed,as_s_S)

always += $(out)/rap.s

clean-files += *.so
