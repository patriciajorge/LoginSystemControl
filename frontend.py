import tkinter as tk
from tkinter.font import Font
from tkinter import ttk, messagebox
from PIL import Image, ImageTk, ImageFilter
from backend import Backend
import re

class LoginApp:
    def __init__(self, root, backend):
        """
        Inicializa a aplicação de login.

        :param root: A janela principal do Tkinter.
        """
        self.root = root
        self.backend = backend
        self.root.title("Login")
        self.root.geometry("400x650")
        self.root.resizable(False, False)

        # Configura estilos
        self.setup_styles()

        # Campos de login (exibidos por padrão)
        self.create_signin_widgets()

    def setup_styles(self):
        """
        Configura os estilos da tela.
        """
        # Fundo escuro com imagem de fundo
        self.bg_image = Image.open("background_image.jpg")
        self.bg_image = self.bg_image.resize((400, 650), Image.Resampling.LANCZOS)
        self.bg_blurred = self.bg_image.filter(ImageFilter.GaussianBlur(10))
        self.bg_blurred_photo = ImageTk.PhotoImage(self.bg_blurred)

        # Cria um canvas para a imagem de fundo
        self.canvas = tk.Canvas(self.root, width=400, height=650)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.create_image(0, 0, image=self.bg_blurred_photo, anchor="nw")

        # Frame principal para o formulário
        self.main_frame = tk.Frame(self.root, bg="black")
        self.main_frame.place(relx=0.5, rely=0.5, anchor="center", width=350, height=550)

    def create_signin_widgets(self):
        """
        Cria e posiciona os widgets da tela de login.
        """
        self.clear_widgets()

        self.signin_label = tk.Label(self.main_frame, text="SIGN IN", fg="#ff5f8f", bg="black", font=("Arial", 18, "bold", 'underline'))
        self.signin_label.place(x=50, y=20)
        self.signin_label.bind("<Button-1>", self.signin_clicked)
        self.signin_label.bind("<Enter>", self.on_enter_signin)
        self.signin_label.bind("<Leave>", self.on_leave_signin)

        self.signup_label = tk.Label(self.main_frame, text="SIGN UP", fg="#9F2349", bg="black", font=("Arial", 18))
        self.signup_label.place(x=210, y=20)
        self.signup_label.bind("<Button-1>", self.signup_clicked)
        self.signup_label.bind("<Enter>", self.on_enter_signup)
        self.signup_label.bind("<Leave>", self.on_leave_signup)

        self.email_label = tk.Label(self.main_frame, text="Email", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.email_label.place(x=20, y=80)
        self.email_entry = tk.Entry(self.main_frame, font=("Arial", 10), width=44, bg="#1a0727", fg="white", bd=2, relief="flat")
        self.email_entry.place(x=20, y=110, height=30)
        self.email_entry.bind("<FocusIn>", self.on_focus_in)
        self.email_entry.bind("<FocusOut>", self.on_focus_out)

        self.password_label = tk.Label(self.main_frame, text="Password", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.password_label.place(x=20, y=170)
        self.password_entry = tk.Entry(self.main_frame, font=("Arial", 10), width=44, bg="#1a0727", fg="white", bd=2, relief="flat", show="*")
        self.password_entry.place(x=20, y=200, height=30)
        self.password_entry.bind("<FocusIn>", self.on_focus_in)
        self.password_entry.bind("<FocusOut>", self.on_focus_out)

        self.signin_button = tk.Button(self.main_frame, text="LOGIN", bg="#ff5f8f", fg="white", font=("Arial", 14, "bold"), bd=0, relief="flat", command=self.login)
        self.signin_button.place(x=20, y=302, width=310, height=50)

    def login(self):
        """
        Realiza o login do usuário.
        """
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()

        if not email or not password:
            messagebox.showwarning('Error', 'All fields must be filled out')
            return

        result = self.backend.login(email, password)
        if result == 'success':                
            # Cria e configura a janela de boas-vindas
            self.welcome_window = tk.Toplevel(self.root)
            self.welcome_window.title('Welcome')
            self.welcome_window.geometry('600x400')

            # Exibe o GIF animado na janela de boas-vindas
            self.gif_player = GIFPlayer(self.welcome_window, "welcome.gif", delay=30)
            self.gif_player.pack()

            # Oculta a janela de login antes de abrir a tela de boas-vindas
            self.root.withdraw()

            # Botão para voltar a tela de login
            ttk.Button(self.welcome_window, text='Back', command=self.back_to_login).pack(pady=10, side='bottom', anchor='w')

        elif result == 'locked':
            messagebox.showwarning('Locked', 'Account is locked. Please try again later.')
        elif result == 'invalid_password' or result == 'invalid_email':
            messagebox.showwarning('Invalid', 'Invalid password or e-mail')

    def create_signup_widgets(self):
        """
        Cria e posiciona os widgets da tela de registro.
        """
        self.clear_widgets()

        self.signup_title = tk.Label(self.main_frame, text="SIGN UP", fg="#ff5f8f", bg="black", font=("Arial", 18, "bold"))
        self.signup_title.place(x=130, y=20)

        # USERNAME
        self.username_label = tk.Label(self.main_frame, text="Username", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.username_label.place(x=20, y=80)
        self.username_entry = tk.Entry(self.main_frame, font=("Arial", 10), width=44, bg="#1a0727", fg="white", bd=2, relief="flat")
        self.username_entry.place(x=20, y=110, height=30)
        self.username_entry.bind("<FocusIn>", self.on_focus_in)
        self.username_entry.bind("<FocusOut>", self.on_focus_out)

        # E-MAIL
        self.email_label = tk.Label(self.main_frame, text="Email", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.email_label.place(x=20, y=150)
        self.email_entry = tk.Entry(self.main_frame, font=("Arial", 10), width=44, bg="#1a0727", fg="white", bd=2, relief="flat")
        self.email_entry.place(x=20, y=180, height=30)
        self.email_entry.bind("<FocusIn>", self.on_focus_in)
        self.email_entry.bind("<FocusOut>", self.on_focus_out)

        # Adiciona o binding para converter o texto para minúsculas no campo de e-mail de registro
        self.email_entry.bind('<KeyRelease>', self.lowercase_email)

        # PASSWORD
        self.password_label = tk.Label(self.main_frame, text="Password", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.password_label.place(x=20, y=220)
        self.password_entry = tk.Entry(self.main_frame, font=("Arial", 10), width=44, bg="#1a0727", fg="white", bd=2, relief="flat", show="*")
        self.password_entry.place(x=20, y=250, height=30)
        self.password_entry.bind("<FocusIn>", self.on_focus_in)
        self.password_entry.bind("<FocusOut>", self.on_focus_out)

        # CONFIRM PASSWORD
        self.confirm_password_label = tk.Label(self.main_frame, text="Confirm Password", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.confirm_password_label.place(x=20, y=290)
        self.confirm_password_entry = tk.Entry(self.main_frame, font=("Arial", 10), width=44, bg="#1a0727", fg="white", bd=2, relief="flat", show="*")
        self.confirm_password_entry.place(x=20, y=320, height=30)
        self.confirm_password_entry.bind("<FocusIn>", self.on_focus_in)
        self.confirm_password_entry.bind("<FocusOut>", self.on_focus_out)

        self.keep_signed_in = tk.Checkbutton(self.main_frame, text="I agree all statements in of ", fg="#ff5f8f", bg="black", font=("Arial", 10), activebackground="black", activeforeground="#ff5f8f",selectcolor="black")
        self.keep_signed_in.place(x=20, y=360)

        underline_font = Font(family="Arial", size=10, underline=True)
        self.terms_label = tk.Label(self.main_frame, text="Terms of Service", fg="#9F2349", bg="black", font=underline_font, cursor="hand2")
        self.terms_label.place(x=200, y=361)

        # Botão para salvar as informações e voltar para a tela de login
        self.signup_button = tk.Button(self.main_frame, text="SIGN UP", command=self.register, bg="#ff5f8f", fg="white", font=("Arial", 14, "bold"), bd=0, relief="flat")
        self.signup_button.place(x=20, y=410, width=310, height=50)

        # Label com o texto 'Already have an account?'
        self.have_account_label = tk.Label(self.main_frame, text="Already have an account?", fg="#ff5f8f", bg="black", font=("Arial", 10))
        self.have_account_label.place(x=65, y=470)

        self.signin_label = tk.Label(self.main_frame, text="Sign in", fg="#9F2349", bg="black", font=underline_font, cursor="hand2")
        self.signin_label.place(x=217, y=469)
        self.signin_label.bind("<Button-1>", self.signin_clicked)
        self.signin_label.bind("<Enter>", lambda e: e.widget.config(fg="#ff5f8f"))
        self.signin_label.bind("<Leave>", lambda e: e.widget.config(fg="#9F2349"))

        self.keep_signed_in_var = tk.BooleanVar()
        self.keep_signed_in = tk.Checkbutton(
            self.main_frame,
            text="I agree to all statements in",
            fg="#ff5f8f",
            bg="black",
            font=("Arial", 10),
            activebackground="black",
            activeforeground="#ff5f8f",
            selectcolor="black",
            variable=self.keep_signed_in_var
        )
        self.keep_signed_in.place(x=20, y=360)

    def register(self):
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        if not username or not email or not password or not confirm_password:
            messagebox.showwarning('Error', 'All fields must be filled out')
            return

        if password != confirm_password:
            messagebox.showwarning('Error', 'Passwords do not match')
            return

        if not self.keep_signed_in_var.get():
            messagebox.showwarning('Error', 'You must agree to the terms of service')
            return

        if not self.validate_email(email):
            messagebox.showwarning('Error', 'Invalid email address')
            return
        try:
            result = self.backend.register_on_database(username, email, password)
            if result == 'Registered':
                messagebox.showinfo('Success', 'Registration successful.')
                self.create_signin_widgets()
            elif result == 'exists':
                messagebox.showwarning('Error', 'User already exists')
        except Exception as e:
            messagebox.showerror('Error', f'An error occurred: {str(e)}')
            return
            
    def validate_email(self, email):
        """
        Valida se o e-mail está no formato correto.

        :param email: O e-mail a ser validado.
        :return: True se o e-mail for válido, False caso contrário.
        """
        # Define a regex para validação do e-mail
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def lowercase_email(self, event):
        """
        Converte o texto do campo de e-mail para letras minúsculas na tela de registro.
        """
        email = self.email_entry.get()
        self.email_entry.delete(0, tk.END)
        self.email_entry.insert(0, email.lower())
    
    def clear_widgets(self):
        """
        Remove todos os widgets do frame principal.
        """
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def signin_clicked(self, event):
        """
        Altera para a tela de login.
        """
        self.create_signin_widgets()

    def signup_clicked(self, event):
        """
        Altera para a tela de registro.
        """
        self.create_signup_widgets()

    def on_enter_signin(self, event):
        """
        Altera a cor do texto quando o mouse entra na área da label de login.
        """
        event.widget.config(fg="#ff007f", font=("Arial", 18, "bold", "underline"))

    def on_leave_signin(self, event):
        """
        Restaura a cor do texto quando o mouse sai da área da label de login.
        """
        event.widget.config(fg="#ff5f8f", font=("Arial", 18, "bold"))

    def on_enter_signup(self, event):
        """
        Altera a cor do texto quando o mouse entra na área da label de registro.
        """
        event.widget.config(fg="#ff007f", font=("Arial", 18, "bold", "underline"))

    def on_leave_signup(self, event):
        """
        Restaura a cor do texto quando o mouse sai da área da label de registro.
        """
        event.widget.config(fg="#9F2349", font=("Arial", 18))
    
    def on_focus_in(self, event):
        """
        Altera a borda do campo de entrada para rosa quando o campo recebe o foco.
        """
        event.widget.config(highlightthickness=2, highlightbackground="#ff5f8f", highlightcolor="#ff5f8f")

    def on_focus_out(self, event):
        """
        Restaura a borda do campo de entrada quando o campo perde o foco.
        """
        event.widget.config(bd=2, highlightthickness=0)

    
    def back_to_login(self):
        """
        Retorna à tela de login a partir da janela de boas-vindas.
        """
        self.welcome_window.destroy()
        self.root.deiconify()

class GIFPlayer(tk.Label):
    def __init__(self, master, file_path, delay=100):
        """
        Inicializa o player de GIF.

        :param master: A janela ou frame onde o GIF será exibido.
        :param file_path: Caminho para o arquivo GIF.
        :param delay: Atraso entre frames em milissegundos.
        """
        super().__init__(master)
        self.file_path = file_path
        self.delay = delay
        self.frames = self.load_gif_frames()
        self.current_frame = 0
        self.configure(image=self.frames[self.current_frame])
        self.update_frame()

    def load_gif_frames(self):
        """
        Carrega os frames do GIF.
        """
        frames = []
        with Image.open(self.file_path) as img:
            while True:
                frames.append(ImageTk.PhotoImage(img.copy()))
                try:
                    img.seek(img.tell() + 1)
                except EOFError:
                    break
        return frames

    def update_frame(self):
        """
        Atualiza o frame atual do GIF.
        """
        self.current_frame = (self.current_frame + 1) % len(self.frames)
        self.configure(image=self.frames[self.current_frame])
        self.after(self.delay, self.update_frame)