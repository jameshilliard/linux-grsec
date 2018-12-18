$(HOSTLIBS)-y += respectre_plugin.so
always := $($(HOSTLIBS)-y)

respectre_plugin-objs := $(patsubst $(srctree)/$(src)/%.c,%.o,$(wildcard $(srctree)/$(src)/*.c))

clean-files += *.so
