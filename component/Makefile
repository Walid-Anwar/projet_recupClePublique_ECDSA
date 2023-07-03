CPPFLAGS += `python3-config --includes`
CPPFLAGS += -I/home/walidanwar999/botan-2.18.2/build/include/

LIBS=`python3-config --ldflags`
LIBS += -lbotan-2

COMPOSANT = projet_signature_ECDSA

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

all: test $(LIBSO)

$(LIBSO): $(LIBSO_OBJS)
	g++ -shared $(LIBSO_OBJS) -o $(LIBSO) $(LIBS)

$(LIBSO_OBJS): ${COMPOSANT}.cpp
	g++ -c ${COMPOSANT}.cpp -o ${COMPOSANT}.o $(CPPFLAGS)

test: $(LIBSO)
	echo "Execution du test"
	python3 test.py

clean:
	rm -f $(LIBSO) $(LIBSO_OBJS)

$(DESTINATION_LIBSO): $(LIBSO)
	cp $< $@
