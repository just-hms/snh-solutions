DISABLE=-z execstack -no-pie -fcf-protection=none -z norelro -Wno-format-security
PPC=441
PPNC=443

canaries=$(foreach i,0 1 2,canary$i)
nocanaries=nocanary0

all: $(canaries) $(nocanaries)

canary%: canary.c
	gcc -g $(DISABLE) -fstack-protector -DPORT=$(PPC)$* -DCANARY$* -o canary$* canary.c common.c

nocanary%: canary.c
	gcc -g $(DISABLE) -fno-stack-protector -DPORT=$(PPNC)$* -DCANARY$* -o nocanary$* canary.c common.c

.PHONY: clean
clean:
	rm -f canary? nocanary?

+%:
	@echo $*=$($*)
