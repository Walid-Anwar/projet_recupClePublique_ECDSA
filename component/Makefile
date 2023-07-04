CPPFLAGS += `python3-config --includes`
CPPFLAGS += -I/home/walidanwar999/botan-2.18.2/build/include/
CPPFLAGS += -fPIC

LIBS=`python3-config --ldflags`
LIBS += -lbotan-2

COMPOSANT = sig_ECDSA

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

all: $(LIBSO)

$(LIBSO): $(LIBSO_OBJS)
	g++ -shared $(LIBSO_OBJS) -o $(LIBSO) $(LIBS) -Wl,-Bsymbolic-functions -Wl,-Bsymbolic -Wl,-z,relro -Wl,-z,now

$(LIBSO_OBJS): ${COMPOSANT}.cpp
	g++ -c ${COMPOSANT}.cpp -o ${COMPOSANT}.o $(CPPFLAGS)

clean:
	rm -f $(LIBSO) $(LIBSO_OBJS)
