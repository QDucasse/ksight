# Kernel-side Hardblare-NG tag initialization

Kernel module and platform driver to set up a ring buffer in DMA and send tag events on syscalls based on LSM hooks.


### Build

> *Note:* The project has been developed with Petalinux in mind, cross-compiling from x64 to aarch64

Two things are needed to build the module: (1) the kernel headers from the build, and (2) the cross-compilation toolchain.

In your Petalinux project, source the sdk with:

```bash
source <path to pl project>/images/linux/sdk/environment-setup-*
```

Using `make` to build the module:

```bash
PL=<petalinux_project> make
```

**BUT** it fails because LSM hooks are not available for modules and should be added to the kernel source directly:

```bash
  MODPOST ksight/Module.symvers
ERROR: modpost: "security_add_hooks" [ksight/ksight.ko] undefined!
ERROR: modpost: "security_hook_heads" [ksight/ksight.ko] undefined!
```