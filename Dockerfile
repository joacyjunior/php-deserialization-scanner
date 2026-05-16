# Usando Alpine Linux como base (Mini Linux)
FROM alpine:latest

# Instalando dependências (PHP para o alvo e Python para o scanner)
RUN apk add --no-cache \
    php82 \
    php82-curl \
    php82-openssl \
    php82-phar \
    python3 \
    py3-requests \
    bash

# Configurando o diretório de trabalho
WORKDIR /app

# Copiando os arquivos do projeto para dentro do Linux
COPY . /app

# Comando padrão (inicia um shell)
CMD ["/bin/bash"]
