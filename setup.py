import sys
import os
from cx_Freeze import setup, Executable

# Lista de arquivos a serem incluídos no build
files = ['login.ico','welcome.gif','background_image.jpg'] 

# Comando para esconder o console
if sys.platform == 'win32':
    base = 'Win32GUI'

config = Executable(
    script='app.py',
    icon='login.ico',
    base=base
)

setup(
    name='LoginSystemControl',
    version='1.0',
    description='This project is a simple login system in Python using Tkinter, with features for user registration and login, as well as account blocking after several failed attempts.',
    author='Patrícia Jorge',
    options={'build_exe': {'include_files': files, 'include_msvcr': True}},
    executables=[config]
)