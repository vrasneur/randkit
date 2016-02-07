FLAGS := -std=gnu11
PROGS:= fdrandom getrandom writefdrandom xor128

all: $(PROGS)

$(PROGS): %: %.c
	gcc $(FLAGS) -o $@ $<

clean:
	rm -f $(PROGS)
