import re
import pandas as pd

def read_first_table_under_heading(file_path, heading):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Find the heading
    heading_pattern = rf'^# {heading}\n+'
    heading_match = re.search(heading_pattern, content, re.MULTILINE)
    if not heading_match:
        raise ValueError(f"Heading '# {heading}' not found in {file_path}")
    
    # Get content after the heading
    start_idx = heading_match.end()
    remaining_content = content[start_idx:]
    
    # Find the first table
    table_pattern = r'(\|[^\n]*\n\|[-|\s:]*\n(?:\|[^\n]*\n)*)'
    table_match = re.search(table_pattern, remaining_content, re.MULTILINE)
    if not table_match:
        raise ValueError("No table found under the specified heading")
    
    table_content = table_match.group(1)
    
    # Process table lines
    lines = table_content.strip().split('\n')
    header = lines[0]
    separator = lines[1]
    data_lines = lines[2:]
    
    # Define column names
    columns = ['Audit Start', 'Audit End', 'Report', 'Tech', 'C', 'H', 'M', 'L', 'I', 'G']
    
    # Process each data row, excluding "Total" row
    data = []
    has_total_row = False
    total_row_line = None
    if data_lines and '**Total**' in data_lines[-1]:
        has_total_row = True
        total_row_line = data_lines[-1]
        data_lines = data_lines[:-1]  # Exclude the Total row
    
    for line in data_lines:
        fields = [field.strip() for field in line.split('|')[1:-1]]  # Skip leading/trailing |
        if len(fields) != len(columns):
            raise ValueError(f"Row has {len(fields)} fields, expected {len(columns)}: {line}")
        data.append(fields)
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=columns)
    
    # Calculate table_end and count newlines after table
    table_end = table_match.end() + start_idx
    if has_total_row:
        table_end -= len(total_row_line) + 1  # Subtract length of Total row and newline
    
    # Count newlines after the table
    post_table_content = content[table_end:]
    newline_count = 0
    for char in post_table_content:
        if char != '\n':
            break
        newline_count += 1
    
    return df, content, table_match.start() + start_idx, table_end, has_total_row, newline_count, total_row_line

def calculate_totals(df):
    # Calculate sums, treating 'n/a' as 0
    sums = {}
    for col in ['C', 'H', 'M', 'L', 'I', 'G']:
        if col == 'C':
            sums[col] = df[col].replace('n/a', 0).astype(int).sum()
        else:
            sums[col] = df[col].astype(int).sum()
    return sums, len(df)

def create_total_row(sums, num_rows):
    return f"|             | **Total**  |                                                                                           | _({num_rows} reports)_      | {sums['C']} | {sums['H']} | {sums['M']} | {sums['L']} | {sums['I']} | {sums['G']} |"

def update_readme(file_path):
    try:
        # Read table and content
        df, content, table_start, table_end, has_total_row, newline_count, total_row_line = read_first_table_under_heading(file_path, 'Cyfrin Audit Reports')
        
        # Calculate totals
        sums, num_rows = calculate_totals(df)
        
        # Create new total row
        total_row = create_total_row(sums, num_rows)
        
        # Create newline string to preserve spacing, adding one for the Total row's own line
        newlines = '\n' * (newline_count + 1) if newline_count > 0 else '\n'
        
        # Insert total row on a new line at the end of the table
        if has_total_row:
            # Overwrite existing Total row, preserving newlines
            # Skip the old Total row and its trailing newline
            new_content = content[:table_end] + total_row + newlines + content[table_end + len(total_row_line) + 1:]
        else:
            # Append new Total row, preserving newlines
            new_content = content[:table_end] + total_row + newlines + content[table_end:]
        
        # Save updated content
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content)
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    update_readme("README.md")