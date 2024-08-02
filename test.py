import os

def find_file_in_path(filename):
    # Get the PATH environment variable
    path_env = os.environ.get('PATH')
    print(path_env)
    
    if not path_env:
        print("PATH environment variable not found.")
        return
    
    # Split the PATH into individual directories
    directories = path_env.split(os.pathsep)
    
    # Iterate over each directory in the PATH
    for directory in directories:
        # Create the full path to the file
        full_path = os.path.join(directory, filename)
        
        # Check if the file exists in the current directory
        if os.path.isfile(full_path):
            print(f"File '{filename}' found in directory: {directory}")
        else:
            continue


find_file_in_path("api-ms-win-core-localization-l1-2-0.dll")




