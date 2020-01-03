all:
	pdflatex smherwig-sandbox-bsdcan2017.tex
	biber smherwig-sandbox-bsdcan2017
	pdflatex smherwig-sandbox-bsdcan2017.tex

clean:
	rm -f smherwig-sandbox-bsdcan2017.pdf
	rm -f smherwig-sandbox-bsdcan2017.aux
	rm -f smherwig-sandbox-bsdcan2017.log
	rm -f smherwig-sandbox-bsdcan2017.bcf
	rm -f smherwig-sandbox-bsdcan2017.blg
	rm -f smherwig-sandbox-bsdcan2017.bbl
	rm -f smherwig-sandbox-bsdcan2017.run.xml

.PHONY: all clean
