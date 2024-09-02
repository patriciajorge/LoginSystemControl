# LoginSystemControl

Este projeto é um sistema de login simples desenvolvido com a biblioteca Tkinter do Python. Inclui funcionalidades para registro de usuário e login, com bloqueio de conta após várias tentativas de login malsucedidas.

## Funcionalidades

- **Registro de Usuário**: Registre um novo usuário com nome de usuário, e-mail e senha.
- **Login**: Usuários podem fazer login usando seu e-mail e senha.
- **Bloqueio de Conta**: Contas são bloqueadas após 5 tentativas falhas de login e desbloqueadas após 5 minutos.
- **GIF Animado**: Exibe um GIF animado após um login bem-sucedido.

## Requisitos

- Python 3.x
- Tkinter (geralmente incluído com o Python)
- Biblioteca `Pillow` para manipulação de imagens
- `bcrypt` para hashing de senhas
- `imageio` para manipulação de GIFs
- `ttkthemes` para widgets temáticos

Para instalar as bibliotecas necessárias, você pode usar o pip:

```bash
pip install -r requirements.txt
```

## Uso

Execute a aplicação:
```bash
python app.py
```

- Registro: Clique em "Register" na tela de login para criar uma nova conta de usuário.
- Login: Insira seu e-mail e senha para fazer login. Após 5 tentativas falhas, sua conta será bloqueada por 5 minutos.
- GIF Animado: Após um login bem-sucedido, um GIF animado será exibido em uma nova janela.


## Solução de Problemas

- Conta Bloqueada: Se sua conta estiver bloqueada, aguarde 5 minutos antes de tentar fazer login novamente.
- Bibliotecas Faltando: Certifique-se de que todas as bibliotecas necessárias estão instaladas.

## Contribuindo

Sinta-se à vontade para fazer um fork deste repositório e fazer melhorias ou relatar problemas. Contribuições são bem-vindas!
