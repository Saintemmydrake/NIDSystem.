from cx_Freeze import setup, Executable

# Define the application name and version
app_name = "Saint's NIDS"  # Change this to your app name
version = "1.0"  # Version number

# Define your script and any additional options
executables = [
    Executable("NIDS.py", base=None)  # Use base="Win32GUI" for GUI apps
]
options = {
    'build_exe':'C:/Users/USER/.spyder-py3'
    }
# Setup configuration
setup(
    name=app_name,
    version=version,
    description="A description of your application.",
    executables=executables,
)

# If you have additional data files, uncomment and adjust the following line
# options = {
#     'build_exe': {
#         'include_files': ['data_file.txt', 'config.ini']  # Add any files you need
#     }
# }
# setup(options=options, executables=executables)