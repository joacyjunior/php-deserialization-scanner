# PHP Insecure Deserialization Scanner (Fingerprinter)

Este é um scanner avançado de reconhecimento (fuzzing) para identificar falhas de desserialização insegura em aplicações PHP.

## 🚀 Funcionalidades
- **Smart Discovery:** Detecta automaticamente parâmetros (Cookies, GET, POST) que parecem conter objetos serializados.
- **100+ Probes:** Biblioteca completa de táticas para forçar o servidor a revelar a vulnerabilidade através de erros de sintaxe, autoloading e side-channels de tempo.
- **Detecção de Phar:** Identifica pontos de entrada para ataques via wrapper `phar://`.
- **Análise de Impressões Digitais:** Monitora warnings do PHP, erros de offset e classes não encontradas.

## 🛠️ Como Usar

### Modo Automático (Descoberta Inteligente)
```bash
python scanner.py http://alvo.com/pagina.php
```

### Modo Manual
```bash
python scanner.py <URL> <PARAMETRO> <METODO: get|post|cookie>
```

## ⚠️ Aviso Legal
Esta ferramenta foi desenvolvida exclusivamente para fins educacionais e testes de penetração autorizados. O uso em sistemas sem permissão é ilegal.
