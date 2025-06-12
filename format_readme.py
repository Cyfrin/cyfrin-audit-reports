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

def calculate_averages(df):
    # Calculate averages, treating 'n/a' as 0
    # Create a copy to avoid SettingWithCopyWarning
    df = df.copy()
    avgs = {}
    # Compute AVG(C+H)
    df['C+H'] = df['C'].replace('n/a', 0).astype(int) + df['H'].astype(int)
    avgs['C+H'] = df['C+H'].mean()
    avgs['C+H'] = int(avgs['C+H']) if avgs['C+H'].is_integer() else round(avgs['C+H'], 2)
    
    # Compute averages for M, L, I, G
    for col in ['M', 'L', 'I', 'G']:
        avgs[col] = df[col].astype(int).mean()
        avgs[col] = int(avgs[col]) if avgs[col].is_integer() else round(avgs[col], 2)
    
    return avgs

def create_total_row(sums, num_rows):
    return f"|             | **Total**  |                                                                                           | _({num_rows} reports)_      | {sums['C']} | {sums['H']} | {sums['M']} | {sums['L']} | {sums['I']} | {sums['G']} |"

def create_averages_row(avgs):
    # Format the averages row with values substituted into the label
    values = f"Crit/High {avgs['C+H']}, Medium {avgs['M']}, Low {avgs['L']}, Info {avgs['I']}, Gas {avgs['G']}"
    return f"|  **Average Findings Per Audit** {values} |"

def create_additional_table(df, heading):
    # Filter rows for the heading
    rows = df[df['Tech'].apply(lambda x: any(tech in x for tech in heading_tech_map[heading]))]
    if rows.empty:
        return ""
    
    # Create table header
    table = "| Report                                                                                    | C   | H   | M   | L   | I   | G   |\n"
    table += "| ----------------------------------------------------------------------------------------- | --- | --- | --- | --- | --- | --- |\n"
    
    # Add data rows
    for _, row in rows.iterrows():
        table += f"| {row['Report']} | {row['C']} | {row['H']} | {row['M']} | {row['L']} | {row['I']} | {row['G']} |\n"
    
    # Calculate and add Total row
    sums, num_rows = calculate_totals(rows)
    table += f"|                                                                **Total**  _({num_rows} reports)_ | {sums['C']} | {sums['H']} | {sums['M']} | {sums['L']} | {sums['I']} | {sums['G']} |\n"
    
    # Calculate and add Averages row
    avgs = calculate_averages(rows)
    table += create_averages_row(avgs) + "\n"
    
    return table

def map_tech_to_headings():
    return {
        'Liquid Staking': ['Liquid Staking'],
        'CLM/DEX/AMM/Concentrated Liquidity': ['AMM', 'DEX', 'CLM', 'Concentrated'],
        'Cross-Chain': ['Cross-Chain', 'Wormhole', 'CCIP', 'LayerZero'],
        'DAO': ['DAO'],
        'ERC4626/Vault/Yield': ['ERC4626', 'Vault', 'Yield'],
        'Chainlink Integration': ['Chainlink', 'Gelato'],
        'NFT': ['NFT'],
        'Stablecoin': ['Stablecoin'],
        'ERC4337/Account Abstraction/Smart Wallet': ['ERC4337', 'Account Abstraction', 'Smart Wallet'],
        'Gaming/Lottery': ['Lottery', 'Gaming'],
        'Staking': ['Staking'],
        'RWA/Real World Assets': ['RWA', 'Real-World Assets', 'Real World Asset'],
        'Token Sale/Crowd Funding': ['Token Sale', 'Crowdfunding', 'Crowd Funding'],
        'Perpetuals / Leverage / Lending / Borrowing': ['Leverage', 'Lending', 'Borrowing', 'Trading', 'Perpetual']
    }

def update_readme(file_path):
    global heading_tech_map
    heading_tech_map = map_tech_to_headings()
    
    try:
        # Read first table and content
        df, content, table_start, table_end, has_total_row, newline_count, total_row_line = read_first_table_under_heading(file_path, 'Cyfrin Audit Reports')
        
        # Calculate totals for first table
        sums, num_rows = calculate_totals(df)
        total_row = create_total_row(sums, num_rows)
        
        # Update first table's Total row
        newlines = '\n' * (newline_count + 1) if newline_count > 0 else '\n'
        if has_total_row:
            new_content = content[:table_end] + total_row + newlines + content[table_end + len(total_row_line) + 1:]
        else:
            new_content = content[:table_end] + total_row + newlines + content[table_end:]
        
        # Find existing additional tables
        additional_content = content[table_end + len(total_row) + newline_count:]
        existing_tables = {}
        for heading in heading_tech_map.keys():
            heading_pattern = rf'\n\n## {re.escape(heading)}\n\n{re.escape("| Report                                                                                    | C   | H   | M   | L   | I   | G   |")}\n\|[-|\s:]*\n(?:\|[^\n]*\n)*'
            match = re.search(heading_pattern, additional_content, re.MULTILINE)
            if match:
                existing_tables[heading] = (match.start() + table_end + len(total_row) + newline_count, match.end() + table_end + len(total_row) + newline_count)
        
        # Calculate report counts and AVG(C+H) for each heading
        heading_metrics = {}
        for heading in heading_tech_map.keys():
            rows = df[df['Tech'].apply(lambda x: any(tech in x for tech in heading_tech_map[heading]))]
            if not rows.empty:
                report_count = len(rows)
                avgs = calculate_averages(rows)
                heading_metrics[heading] = (report_count, avgs['C+H'])
            else:
                heading_metrics[heading] = (0, 0)  # No reports, lowest priority
        
        # Sort headings by report count (descending), then AVG(C+H) (descending), then alphabetically
        sorted_headings = sorted(heading_tech_map.keys(), key=lambda h: (-heading_metrics[h][0], -heading_metrics[h][1], h))
        
        # Generate new additional tables in sorted order
        additional_tables_content = ""
        for heading in sorted_headings:
            table_content = create_additional_table(df, heading)
            if table_content:
                additional_tables_content += f"\n\n## {heading}\n\n{table_content}\n"
        
        # Replace or append additional tables
        if existing_tables:
            # Find the earliest and latest positions of existing tables
            min_start = min(start for start, _ in existing_tables.values())
            max_end = max(end for _, end in existing_tables.values())
            new_content = new_content[:min_start] + additional_tables_content + new_content[max_end:]
        else:
            # Append at the end of the file
            new_content = new_content.rstrip('\n') + additional_tables_content
        
        # Save updated content
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content)
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    update_readme("README.md")