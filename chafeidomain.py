import os

def split_file(file_path, lines_per_file, output_prefix, output_dir):
    """
    Splits a file into multiple files with a specified number of lines per file.
    
    :param file_path: The path to the input file.
    :param lines_per_file: The number of lines each split file should contain.
    :param output_prefix: The prefix for naming the output files.
    :param output_dir: The directory where the output files should be saved.
    """
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    with open(file_path, 'r') as file:
        file_number = 1
        line_count = 0
        output_file_path = os.path.join(output_dir, f"{output_prefix}_{file_number}.log")
        output_file = open(output_file_path, 'w')

        for line in file:
            if line_count == lines_per_file:
                output_file.close()
                file_number += 1
                line_count = 0
                output_file_path = os.path.join(output_dir, f"{output_prefix}_{file_number}.log")
                output_file = open(output_file_path, 'w')
            
            output_file.write(line)
            line_count += 1

        output_file.close()

def main():
    # Directory to save the split files
    output_dir = 'chains'

    # List of log files to be processed
    log_files = [f"output_{i}.log" for i in range(1, 3)] + ["output_1.log~"]
    lines_per_file = 2000

    for log_file in log_files:
        # Ensure the file exists
        if os.path.exists(log_file):
            # Extract the base name without extension for the prefix
            base_name = log_file.rsplit('.', 1)[0]
            split_file(log_file, lines_per_file, base_name, output_dir)

if __name__ == "__main__":
    main()