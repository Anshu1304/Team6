import subprocess

# List of scripts to execute
scripts = [
    "sqlinjection.py",
    "csrfscaning.py",
    "reflectedxss.py",
    "xssstore.py",
    "xss.dscan.py",
    "sqlmedium.py",
    "csrfmed2.py",
    "reflecetd2xss.py",
    "xssstore2.py",
    "sqlmedium.py",
]

def execute_script(script_name):
    try:
        # Run the script and capture the output
        result = subprocess.run(
            ["python", script_name],
            capture_output=True,
            text=True
        )
        # Print the output of the script
        print(f"Output of {script_name}:\n")
        print(result.stdout)
        print("="*40 + "\n")
    except Exception as e:
        print(f"An error occurred while executing {script_name}: {e}")

def main():
    for script in scripts:
        execute_script(script)

if __name__ == "__main__":
    main()