EXEC   := spd
LDLIBS := -lpcap

all: $(EXEC)

clean:
	$(RM) $(EXEC)

distclean: clean
	$(RM) *.o *~
