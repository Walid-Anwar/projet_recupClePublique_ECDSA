CPPFLAGS += `python3-config --includes`
CPPFLAGS += /usr/local/include/botan-2
LIBS=`python3-config --ldflags`
LIBS += -lbotan-2

COMPOSANT = projet_signature_ECDSA
LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

all: $(LIBSO)

$(LIBSO): $(LIBSO_OBJS)
	g++ -shared $(LIBSO_OBJS) -o $(LIBSO) $(LIBS)

$(LIBSO_OBJS): ${COMPOSANT}.cpp
	g++ -c ${COMPOSANT}.cpp -o ${COMPOSANT}.o $(CPPFLAGS)

clean:
	rm -f $(LIBSO) $(LIBSO_OBJS)
