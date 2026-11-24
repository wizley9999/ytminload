ARCHS = arm64
TARGET = iphone:clang:latest:17.0
DEBUG = 0
FINALPACKAGE = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = ytminload
ytminload_FILES = Tweak.mm
ytminload_CFLAGS = -fobjc-arc -Wall
ytminload_FRAMEWORKS = Foundation Security
ytminload_LDFLAGS = -Wl,-install_name,@rpath/ytminload.dylib

include $(THEOS_MAKE_PATH)/library.mk

BASE ?= ipa
.PHONY: ipa
ipa: all
	python3 ytm.py check "$(BASE)"
	python3 ytm.py pack "$(BASE)" $(THEOS_OBJ_DIR)/ytminload.dylib
