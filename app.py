from frontend import LoginApp
from backend import Backend
from ttkthemes import ThemedTk

if __name__ == "__main__":
    root = ThemedTk()
    backend = Backend()
    app = LoginApp(root, backend)  # Inicializa a interface gráfica e conecta ao backend
    root.mainloop()
