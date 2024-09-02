from datetime import datetime, timedelta
import sqlite3
import bcrypt
from tkinter import messagebox

class Backend:
    def __init__(self):
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

    def login(self, email, password):
        email = email.strip()  # Remove espaços extras
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
                    self.cursor.execute('UPDATE Users SET LoginAttempts = 0 WHERE Email = ?', (email,))
                    self.connect.commit()
                    return 'success'                    
                
                else:
                    # Incrementa o contador de tentativas de login
                    attempts += 1
                    if attempts >= 5:
                        # Bloqueia a conta após 5 tentativas
                        self.cursor.execute('UPDATE Users SET IsLocked = 1 WHERE Email = ?', (email,))
                        messagebox.showwarning('Locked', 'Account is locked due to too many failed login attempts.')
                    else:
                        self.cursor.execute('UPDATE Users SET LoginAttempts = ?, LastAttempt = CURRENT_TIMESTAMP WHERE Email = ?', (attempts, email))
                        messagebox.showwarning('Invalid', 'Invalid password or email')

                self.connect.commit()
            
        except Exception as e:
            self.label_erro.config(text='An error occurred during login')

    def register_on_database(self, username, email, password):
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
            self.connect.commit()  # salvar
            return 'Registered'

        except Exception as e:
            messagebox.showerror('Error', f'Error: {e}')

    def unlock_account(self, email):
        """
        Desbloqueia a conta após um período de bloqueio.
        """
        unlock_time = datetime.now() - timedelta(minutes=15)  # 15 minutos de bloqueio
        self.cursor.execute('UPDATE Users SET IsLocked = 0, LoginAttempts = 0 WHERE Email = ? AND LastAttempt < ?', (email, unlock_time))
        self.connect.commit()
