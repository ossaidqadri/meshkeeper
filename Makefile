# meshkeeper as an OpenWrt package. The repo root is the package directory, so
# a release tag is the whole input: no PKG_SOURCE, no download hash to keep in
# sync with the repo.
#
# Two packages from this one Makefile: the daemon (per router CPU) and the
# LuCI page (architecture independent).

include $(TOPDIR)/rules.mk

PKG_NAME:=meshkeeper
# Read from build.zig.zon so the version has one home. The release job checks
# the git tag against the same line.
PKG_VERSION:=$(shell sed -n 's/^[[:space:]]*\.version = "\([^"]*\)".*/\1/p' $(CURDIR)/build.zig.zon)
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Ossaid Quadri <imossaidquadri@gmail.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

# The SDK has no Zig. Zig cross-compiles to musl by itself, so there is no
# toolchain prefix to pass, only a target triple. Pinned to the version in
# build.zig.zon's minimum_zig_version.
ZIG_VERSION:=0.17.0
ZIG_HOST:=zig-x86_64-linux-$(ZIG_VERSION)

define Download/zig
	URL:=https://ziglang.org/download/$(ZIG_VERSION)
	FILE:=$(ZIG_HOST).tar.xz
	HASH:=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
endef
$(eval $(call Download,zig))

# OpenWrt arch -> Zig target triple, plus the CPU where Zig's default for that
# triple is too generic for the routers in the target. Unknown arches stop the
# build instead of silently producing a wrong-CPU binary.
ZIG_TARGET_mips_24kc:=mips-linux-musleabi
ZIG_CPU_mips_24kc:=mips32r2
ZIG_TARGET_mipsel_24kc:=mipsel-linux-musleabi
ZIG_CPU_mipsel_24kc:=mips32r2
ZIG_TARGET_arm_cortex-a7_neon-vfpv4:=arm-linux-musleabihf
ZIG_CPU_arm_cortex-a7_neon-vfpv4:=cortex_a7
ZIG_TARGET_aarch64_cortex-a53:=aarch64-linux-musl
ZIG_CPU_aarch64_cortex-a53:=cortex_a53
ZIG_TARGET_x86_64:=x86_64-linux-musl

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/build.zig $(CURDIR)/build.zig.zon $(CURDIR)/src $(CURDIR)/LICENSE $(PKG_BUILD_DIR)/
	$(TAR) -C $(PKG_BUILD_DIR) -xf $(DL_DIR)/$(ZIG_HOST).tar.xz
endef

define Build/Compile
	$(if $(ZIG_TARGET_$(ARCH_PACKAGES)),,$(error meshkeeper: no Zig target for OpenWrt arch '$(ARCH_PACKAGES)'))
	cd $(PKG_BUILD_DIR) && ./$(ZIG_HOST)/zig build -Drelease \
		-Dtarget=$(ZIG_TARGET_$(ARCH_PACKAGES)) \
		$(if $(ZIG_CPU_$(ARCH_PACKAGES)),-Dcpu=$(ZIG_CPU_$(ARCH_PACKAGES)))
endef

define Package/meshkeeper
	SECTION:=net
	CATEGORY:=Network
	TITLE:=EasyMesh controller for stock-firmware mesh satellites
	URL:=https://github.com/ossaidqadri/meshkeeper
	MAINTAINER:=Ossaid Quadri <imossaidquadri@gmail.com>
	# The init script always jails the daemon.
	# No wpad dependency on purpose: apk refuses to install wpad-mbedtls next
	# to wpad-basic-mbedtls, so it would break the one-command install on a
	# stock router. The README has the swap instead.
	DEPENDS:=+procd-ujail
	# Same uid as the hand-installed copy, so an upgrade keeps file ownership.
	USERID:=meshkeeper=32768:meshkeeper=32768
endef

define Package/meshkeeper/conffiles
/etc/config/meshkeeper
endef

define Package/meshkeeper/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config $(1)/etc/capabilities $(1)/usr/share/acl.d $(1)/lib/upgrade/keep.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zig-out/bin/meshkeeper $(1)/usr/sbin/meshkeeper
	# The learned state is written at runtime, so sysupgrade only keeps it if told to.
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/meshkeeper $(1)/lib/upgrade/keep.d/meshkeeper
	$(INSTALL_BIN) ./files/etc/init.d/meshkeeper $(1)/etc/init.d/meshkeeper
	$(INSTALL_CONF) ./files/etc/config/meshkeeper $(1)/etc/config/meshkeeper
	$(INSTALL_DATA) ./files/etc/capabilities/meshkeeper.json $(1)/etc/capabilities/meshkeeper.json
	$(INSTALL_DATA) ./files/usr/share/acl.d/meshkeeper.json $(1)/usr/share/acl.d/meshkeeper.json
endef

define Package/luci-app-meshkeeper
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=LuCI status page for meshkeeper
	URL:=https://github.com/ossaidqadri/meshkeeper
	MAINTAINER:=Ossaid Quadri <imossaidquadri@gmail.com>
	PKGARCH:=all
	DEPENDS:=+luci-base +meshkeeper
endef

define Package/luci-app-meshkeeper/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/meshkeeper
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/www/luci-static/resources/view/meshkeeper/mesh.js $(1)/www/luci-static/resources/view/meshkeeper/mesh.js
	$(INSTALL_DATA) ./files/usr/share/luci/menu.d/luci-app-meshkeeper.json $(1)/usr/share/luci/menu.d/luci-app-meshkeeper.json
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/luci-app-meshkeeper.json $(1)/usr/share/rpcd/acl.d/luci-app-meshkeeper.json
endef

# LuCI reads its menu and ACL files at login, so the first page view after
# install needs rpcd to re-read them.
define Package/luci-app-meshkeeper/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload
}
endef

$(eval $(call BuildPackage,meshkeeper))
$(eval $(call BuildPackage,luci-app-meshkeeper))
