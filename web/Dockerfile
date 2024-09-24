# Esta linha especifica a imagem base para o contêiner, que será a imagem oficial do Python na versão 3.8.
FROM python:3.8
#Define o diretório de trabalho dentro do contêiner. Qualquer comando executado após esta linha será executado no diretório /app. 
WORKDIR /app
#Copia o arquivo requirements.txt do diretório local (na máquina host) para o diretório de trabalho (/app) dentro do contêiner. Este arquivo geralmente contém as dependências da aplicação.
COPY requirements.txt .
#Executa o comando pip (o gerenciador de pacotes do Python) para instalar todas as dependências listadas no arquivo requirements.txt. O argumento --no-cache-dir é usado para evitar que o pip armazene em cache os arquivos de instalação no contêiner, o que reduz o tamanho da imagem final.
RUN pip install --no-cache-dir -r requirements.txt
#Copia todos os arquivos do diretório atual da máquina host (onde o Dockerfile está localizado) para o diretório de trabalho dentro do contêiner (/app). Isso inclui o código da aplicação.
COPY . .
#Define o comando padrão que será executado quando o contêiner for iniciado. Neste caso, o comando será python app.py, que executa o arquivo app.py, iniciando a aplicação Python.
CMD ["python", "app.py"]