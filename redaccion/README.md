# Redacción

Este directorio está destinado para la documentación y redacción en LaTeX del proyecto.

## Estructura sugerida

```
redaccion/
├── main.tex          # Documento principal
├── chapters/         # Capítulos individuales
├── figures/          # Imágenes y diagramas
├── bibliography.bib  # Referencias bibliográficas
└── compiled/         # PDFs compilados
```

## Compilación

Para compilar el documento LaTeX, típicamente se usa:

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

O con latexmk para automatizar:

```bash
latexmk -pdf main.tex
```
