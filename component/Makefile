CPPFLAGS += `python3-config --includes`
CPPFLAGS += CPPFLAGS += -I/home/walidanwar999/botan/include/botan-2
LIBS=`python3-config --ldflags`
LIBS += -lbotan-2

COMPOSANT = projet_signature_ECDSA

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

all: test $(LIBSO)

include ../gcc.mk
include ../pybind11.mk

test: $(LIBSO)
	echo "execution du test"
	python3 test.py
	
clean:
	rm -f ${LIBSO} ${LIBSO_OBJS}

${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@
