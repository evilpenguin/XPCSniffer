THEOS_DEVICE_IP = 127.0.0.1
THEOS_DEVICE_PORT = 2222
DEBUG = 1

include $(THEOS)/makefiles/common.mk

TARGET := iphone:13.0
ARCHS := arm64 arm64e
TWEAK_NAME = XPCSniffer
$(TWEAK_NAME)_FILES = Tweak.xm
$(TWEAK_NAME)_CFLAGS += -DTHEOS_LEAN_AND_MEAN -Wno-shift-negative-value -Wno-int-to-pointer-cast
$(TWEAK_NAME)_FRAMEWORKS = CoreFoundation Foundation

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
