LUNATIK := lunatik/lua

subdir-ccflags-y := -I${PWD}/${LUNATIK} \
	-Wall \
	-D_KERNEL \
    -D_MODULE \
	-D'CHAR_BIT=(8)' \
	-D'MIN=min' \
	-D'MAX=max' \
	-D'UCHAR_MAX=(255)' \
	-D'UINT64_MAX=((u64)~0ULL)'

obj-y += lunatik/
obj-$(CONFIG_KTLS) += tls.o
tls-$(CONFIG_KTLS) := tls_main.o tls_sw.o tls_device.o tls_device_fallback.o