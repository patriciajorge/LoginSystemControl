from tkinter import messagebox
from ttkthemes import ThemedTk
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import imageio
import sys
import os

class LoginApp:
    def __init__(self, root):
        """
        Inicializa a aplicação de login.

        :param root: A janela principal do Tkinter.
        """
        self.root = root
        self.root.title('Login')
        self.root.geometry('400x400')

        # Conecta ao banco de dados ou cria um
        self.connect = sqlite3.connect('users.db')
        self.cursor = self.connect.cursor()

        # Garantir que a tabela Users seja criada ao iniciar a aplicação
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            Email TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL,
            LoginAttempts INTEGER DEFAULT 0,
            IsLocked INTEGER DEFAULT 0,
            LastAttempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')
        self.connect.commit()

        # Configura fonte e estilos dos widgets
        self.font = ('Roboto', 14)
        self.setup_styles()  
        self.create_login_widgets()

    def setup_styles(self):
        """
        Configura os estilos dos widgets.
        """
        style = ttk.Style()
        style.configure('TLabel', font=self.font)
        style.configure('TButton', font=self.font)

    def create_login_widgets(self):
        """
        Cria e posiciona os widgets da tela de login.
        """
        # Configurando o layout da janela de login(root)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(2, weight=1)

        # Adicionando os widgets
        ttk.Label(self.root, text='Welcome back!', font=self.font).grid(row=0, column=1, padx=0, pady=20, sticky='ew')

        # E-MAIL
        ttk.Label(self.root, text='E-mail', font=self.font).grid(row=1, column=0, padx=15, pady=20, sticky='w')
        self.entry_email = ttk.Entry(self.root, width=30)  
        self.entry_email.grid(row=1, column=1, padx=(0, 0), pady=1)

        # PASSWORD
        ttk.Label(self.root, text='Password', font=self.font).grid(row=2, column=0, padx=15, pady=20, sticky='w')
        self.entry_pass = ttk.Entry(self.root, show='*', width=30)  # Ajuste a largura conforme necessário
        self.entry_pass.grid(row=2, column=1, padx=(0, 0), pady=1)

        # MENSAGEM DE ERRO!
        self.label_erro = ttk.Label(self.root, text='')
        self.label_erro.grid(row=3, column=0, columnspan=2, pady=10)

        # Botão para entrar(login)
        ttk.Button(self.root, text='Login', command=self.login).grid(row=6, column=0, columnspan=1, pady=30)
       
       # Botão para cadastrar(register)
        ttk.Button(self.root, text='Register', command=self.create_register_widgets).grid(row=6, column=1, columnspan=2, pady=30)

    def login(self):
        """
        Realiza o login do usuário.
        """
        email = self.entry_email.get().strip()
        password = self.entry_pass.get().strip()

        # Verifica se os campos estão preenchidos
        if not email or not password:
            messagebox.showwarning('Error', 'All fields must be filled out')
            return

        password = password.encode('utf-8')

        # faz uma consulta no banco de dados para verificar se os dados estão registrados
        try:
            self.cursor.execute('SELECT Email, Password, LoginAttempts, IsLocked, LastAttempt FROM Users WHERE Email = ?', (email,))
            result = self.cursor.fetchone()

            if result:
                stored_password, attempts, is_locked, last_attempt = result[1], result[2], result[3], result[4]

                # Verifica se a conta está bloqueada e se o tempo de bloqueio passou
                if is_locked:
                    unlock_time = datetime.strptime(last_attempt, '%Y-%m-%d %H:%M:%S') + timedelta(minutes=15)
                    if datetime.now() < unlock_time:
                        messagebox.showwarning('Locked', 'Account is locked. Please try again after 5 minutes.')
                        return
                    else:
                        # Desbloquear a conta se o tempo de bloqueio passou
                        self.cursor.execute('UPDATE Users SET IsLocked = 0, LoginAttempts = 0 WHERE Email = ?', (email,))
                        self.connect.commit()

                # Verifica se a senha está correta
                if bcrypt.checkpw(password, stored_password):
                    # Cria e configura a janela de boas-vindas
                    self.welcome_window = tk.Toplevel(self.root)
                    self.welcome_window.title('Welcome')
                    self.welcome_window.geometry('600x400')

                    # Exibe o GIF animado na janela de boas-vindas
                    self.gif_player = GIFPlayer(self.welcome_window, "welcome.gif", delay=30)
                    self.gif_player.pack()

                    # Oculta a janela de login antes de abrir a tela de boas-vindas
                    self.root.withdraw()

                    # botão para voltar a tela de login
                    ttk.Button(self.welcome_window, text='Back', command=self.go_back_to_login).pack(pady=10, side='bottom', anchor='w')

                else:
                    # Incrementa o contador de tentativas de login
                    attempts += 1
                    if attempts >= 5:
                        # Bloqueia a conta após 5 tentativas
                        self.cursor.execute('UPDATE Users SET IsLocked = 1 WHERE Email = ?', (email,))
                        messagebox.showwarning('Locked', 'Account is locked due to too many failed login attempts.')
                    else:
                        self.cursor.execute('UPDATE Users SET LoginAttempts = ?, LastAttempt = CURRENT_TIMESTAMP WHERE Email = ?', (attempts, email))
                        messagebox.showwarning('Invalid', 'Invalid password')

                self.connect.commit()

            # Validação de e-mail
            else:
                messagebox.showwarning('Invalid', 'Email not found')
        except Exception as e:
            self.label_erro.config(text='An error occurred during login')

    def go_back_to_login(self):
        """
        Retorna à tela de login a partir da tela de boas-vindas ou da tela de registro.
        """
        if hasattr(self, 'welcome_window') and self.welcome_window:
            self.welcome_window.destroy()  # Fecha a janela de boas-vindas, se existir
            
        self.root.deiconify()  # Reexibe a janela de login
        self.new_window.withdraw() # fecha a janela de registro antes de voltar para a tela de login

    def create_register_widgets(self):
        """
        Cria e posiciona os widgets da tela de registro.
        """
        # Fecha a janela principal (login) antes de criar a de registro
        self.root.withdraw()

        # Criação da nova janela para registro
        self.new_window = ThemedTk(theme='breeze')  # Usar breeze para a janela de registro
        self.new_window.title('Register')
        self.new_window.geometry('500x300')

        # Definindo widgets na nova janela
        ttk.Label(self.new_window, text='Register', font=self.font).grid(row=0, column=1, padx=0, pady=20, sticky='ew')

        # USERNAME
        ttk.Label(self.new_window, text='Username', font=self.font).grid(row=1, column=0, padx=10, pady=5, sticky='w')
        self.entry_user = ttk.Entry(self.new_window, width=40)  # Ajuste a largura conforme necessário
        self.entry_user.grid(row=1, column=1, padx=10, pady=5, sticky='ew')

        # E-MAIL
        ttk.Label(self.new_window, text='E-mail', font=self.font).grid(row=2, column=0, padx=10, pady=5, sticky='w')
        self.entry_new_email = ttk.Entry(self.new_window, width=40)  # Ajuste a largura conforme necessário
        self.entry_new_email.grid(row=2, column=1, padx=10, pady=5, sticky='ew')
        # Adiciona o binding para converter o texto para minúsculas no campo de e-mail de registro
        self.entry_new_email.bind('<KeyRelease>', self.lowercase_email_register)

        # PASSWORD
        ttk.Label(self.new_window, text='Password', font=self.font).grid(row=3, column=0, padx=10, pady=5, sticky='w')
        self.entry_new_pass = ttk.Entry(self.new_window, show='*', width=40)  # Ajuste a largura conforme necessário
        self.entry_new_pass.grid(row=3, column=1, padx=10, pady=5, sticky='ew')

        # CONFIRM PASSWORD
        ttk.Label(self.new_window, text='Confirm Password', font=self.font).grid(row=4, column=0, padx=10, pady=5, sticky='w')
        self.entry_conf_pass = ttk.Entry(self.new_window, show='*', width=40)  # Ajuste a largura conforme necessário
        self.entry_conf_pass.grid(row=4, column=1, padx=10, pady=5, sticky='ew')

        # Botão de voltar para a tela de login
        ttk.Button(self.new_window, text='Back', command=self.go_back_to_login).grid(row=5, column=0, columnspan=1, padx=1, pady=1, sticky='e')

        # Botão para salvar as informações e volta para a tela de login
        ttk.Button(self.new_window, text='Submit', command=self.register_on_data_base).grid(row=5, column=1, columnspan=2, padx=1, pady=1, sticky='we')

    def register_on_data_base(self):
        """
        Registra um novo usuário no banco de dados.
        """
        username = self.entry_user.get().strip()
        email = self.entry_new_email.get().strip()
        password = self.entry_new_pass.get().strip()
        confirm_pass = self.entry_conf_pass.get().strip()

        # Verifica se todos os campos estão preenchidos
        if not username or not email or not password or not confirm_pass:
            messagebox.showwarning('Error', 'All fields must be filled out')
            return
        
        # Valida o formato do e-mail
        if not self.validate_email(email):
            messagebox.showwarning('Error', 'Email must end with @gmail.com')
            return

        # Verifica se as senhas coincidem
        if password != confirm_pass:
            messagebox.showwarning('Error', 'Passwords do not match')
            return

        # Verifica se o username ou o email já estão registrados
        self.cursor.execute('SELECT * FROM Users WHERE Username = ? OR Email = ?', (username, email))
        if self.cursor.fetchone():
            messagebox.showwarning('Error', 'Username or Email already registered')
            return

        # Criptografar a senha
        password = password.encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        # Salvar os dados no banco de dados
        try:
            self.cursor.execute('INSERT INTO Users (Username, Email, Password) VALUES (?, ?, ?)', (username, email, hashed))
            self.connect.commit() # salvar
            messagebox.showinfo('Success', 'User registered successfully')
            self.new_window.destroy()  # Fecha a janela de registro após o sucesso

            # Reabre a tela de login
            self.root.deiconify()  

        except Exception as e:
            messagebox.showerror('Error', f'Error: {e}')

    def lowercase_email(self, event):
        """
        Converte o texto do campo de e-mail para letras minúsculas.
        """
        email = self.entry_email.get()
        self.entry_email.delete(0, tk.END)
        self.entry_email.insert(0, email.lower())

    def lowercase_email_register(self, event):
        """
        Converte o texto do campo de e-mail para letras minúsculas na tela de registro.
        """
        email = self.entry_new_email.get()
        self.entry_new_email.delete(0, tk.END)
        self.entry_new_email.insert(0, email.lower())
    
    def validate_email(self, email):
        """
        Valida se o e-mail está no formato correto (@gmail.com).

        :param email: O e-mail a ser validado.
        :return: True se o e-mail for válido, False caso contrário.
        """
        return email.endswith('@gmail.com')

    def unlock_account(self, email):
        """
        Desbloqueia a conta após um período de bloqueio.
        """
        unlock_time = datetime.now() - timedelta(minutes=5)  # 5 minutos de bloqueio
        self.cursor.execute('UPDATE Users SET IsLocked = 0, LoginAttempts = 0 WHERE Email = ? AND LastAttempt < ?', (email, unlock_time))
        self.connect.commit()

class GIFPlayer(tk.Label):
    def __init__(self, master=None, file="", delay=30, **kwargs):
        super().__init__(master, **kwargs)
        self.file = file
        self.delay = delay
        self.frames = []
        self.load_gif()
        self.current_frame = 0
        self.update_animation()

    def load_gif(self):
        img = Image.open(self.file)
        self.frames = [ImageTk.PhotoImage(img.copy().convert("RGBA"))]
        while True:
            try:
                img.seek(img.tell() + 1)
                self.frames.append(ImageTk.PhotoImage(img.copy().convert("RGBA")))
            except EOFError:
                break

    def update_animation(self):
        self.config(image=self.frames[self.current_frame])
        self.current_frame = (self.current_frame + 1) % len(self.frames)
        self.after(self.delay, self.update_animation)

if __name__ == '__main__':
    root = ThemedTk(theme='breeze')
    app = LoginApp(root)
    root.mainloop()
