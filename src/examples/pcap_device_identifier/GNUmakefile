DEV_SDK ?= ../../../

ifneq ($(MAKECMDGOALS),clean)
ifndef DPI_SDK
$(error Please set DPI_SDK)
endif
endif

DEVICE_APP := pcap_device_identifier

SRC := \
	main.c \
	parameters.c \
	pdi_device.c \
	packet_dispatch.c \
	dpi_processing.c \
	dpi_result_processing.c \
	device_identification.c

SRC += thread_helper.c

CFLAGS_WARNING += -Wall -Wextra -Wno-comment -Wno-sign-compare -Wno-missing-field-initializers \
                  -Wstrict-prototypes -Wno-unused-parameter -Werror

CFLAGS_DEFINES := -D_GNU_SOURCE

STATIC_LDFLAGS_LIBS = \
        $(DEV_SDK)/lib/libqmdevice.a \
        $(DPI_SDK)/lib/libqmengine.a   \
        $(DPI_SDK)/lib/libqmbundle.a

DYNAMIC_LDFLAGS_LIBS = \
		-L$(DPI_SDK)/lib \
		-L$(DEV_SDK)/lib \
		-lqmengine \
		-lqmbundle \
		-lqmdevice

ifeq ($(STATIC),1)
LDFLAGS_LIBS = $(STATIC_LDFLAGS_LIBS)
else
LDFLAGS_LIBS = $(DYNAMIC_LDFLAGS_LIBS)
endif

# please set CROSS='' and arch specific flags for native build
CROSS ?= 
CFLAGS_ARCH  ?=  -mtune=generic 
LDFLAGS_ARCH ?=

# define default compiler
CC     = $(CROSS)gcc
LD     = $(CROSS)ld

CFLAGS_INCLUDE +=  \
	-I$(DEV_SDK)/include \
	-I$(DPI_SDK)/include -I$(DPI_SDK)/src/include

LDFLAGS_EXTRA_LIBS = -ldl -lm -lpcap -lrt
LDFLAGS_EXTRA_LIBS += -lpthread

ifeq ($(DEBUG),1)
CFLAGS_OPT += -O0 -g
else
CFLAGS_OPT += -O2
endif

CFLAGS  += $(CFLAGS_DEFINES) $(CFLAGS_WARNING) $(CFLAGS_INCLUDE) $(CFLAGS_OPT) $(CFLAGS_ARCH)
LDFLAGS_LIBS += $(LDFLAGS_EXTRA_LIBS)

# application targets

DEP = $(SRC:.c=.d)
%.d: %.c
	$(CC) $(CFLAGS) -M $< -o $@

OBJS = $(SRC:.c=.o)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(DEVICE_APP): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(LDFLAGS_LIBS) -o $@

INSTALLDIR ?= $(DEV_SDK)/src/bin
install: $(DEVICE_APP)
	mkdir -p $(INSTALLDIR)
	cp $(DEVICE_APP) $(INSTALLDIR)/$(DEV_APP)

clean:
	$(RM) $(DEVICE_APP) $(OBJS) $(DEP)

ifneq ($(MAKECMDGOALS),clean)
 -include $(DEP)
endif

.PHONY: clean

.DEFAULT_GOAL := $(DEVICE_APP)
