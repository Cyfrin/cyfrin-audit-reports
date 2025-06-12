import re
import pandas as pd

def read_first_table_under_heading(file_path, heading):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Find the heading
    heading_pattern = rf'^\s*#+\s*{re.escape(heading)}\s*$'
    heading_match = None
    for line in content.splitlines():
        if re.match(heading_pattern, line, re.MULTILINE):
            heading_match = re.search(heading_pattern, line, re.MULTILINE)
            break
    
    if not heading_match:
        raise ValueError(f"Heading '# {heading}' not found in {file_path}")
    
    # Get content after the heading
    start_idx = heading_match.end() + content[heading_match.end():].find('\n') + 1
    remaining_content = content[start_idx:]
    
    # Find the table
    table_pattern = r'(\|[^\n]*\n\|[-|\s:]*\n(?:\|[^\n]*\n)*)'
    table_match = re.search(table_pattern, remaining_content, re.MULTILINE)
    if not table_match:
        raise ValueError("No table found under the specified heading")
    
    table_content = table_match.group(1)
    
    # Normalize line endings and whitespace
    table_content = table_content.replace('\r\n', '\n').replace('\r', '\n')
    table_content = table_content.replace('\xa0', ' ')
    
    # Split lines
    lines = table_content.splitlines()
    valid_lines = [line for line in lines if line.strip()]
    
    if len(valid_lines) < 2:
        raise ValueError(f"Table has insufficient lines: {len(valid_lines)}")
    
    header = valid_lines[0]
    separator = valid_lines[1]
    data_lines = valid_lines[2:]
    
    # Define column names
    columns = ['Audit Start', 'Audit End', 'Report', 'Tech', 'C', 'H', 'M', 'L', 'I', 'G']
    
    # Process data rows, excluding "Total" row
    data = []
    has_total_row = False
    
    for i in range(len(data_lines) - 1, -1, -1):
        fields = [re.sub(r'\s+', ' ', field).strip() for field in data_lines[i].split('|')[1:-1]]
        if len(fields) >= 4 and fields[1] == '**Total**' and '_(' in fields[3]:
            has_total_row = True
            data_lines = data_lines[:i] + data_lines[i+1:]
            break
    
    for line in data_lines:
        fields = [re.sub(r'\s+', ' ', field).strip() for field in line.split('|')[1:-1]]
        if len(fields) == len(columns):
            data.append(fields)
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=columns)
    
    # Calculate table_end and newline_count
    table_end = start_idx + len(table_content.rstrip('\n'))
    post_table_content = content[table_end:]
    newline_count = 0
    for char in post_table_content:
        if char != '\n':
            break
        newline_count += 1
    
    return df, content, table_end, newline_count, has_total_row, header

def calculate_totals(df):
    sums = {}
    for col in ['C', 'H', 'M', 'L', 'I', 'G']:
        if col == 'C':
            sums[col] = df[col].replace('n/a', 0).astype(int).sum()
        else:
            sums[col] = df[col].astype(int).sum()
    return sums, len(df)

def calculate_averages(df):
    df = df.copy()
    avgs = {}
    df['C+H'] = df['C'].replace('n/a', 0).astype(int) + df['H'].astype(int)
    avgs['C+H'] = df['C+H'].mean()
    avgs['C+H'] = int(avgs['C+H']) if avgs['C+H'].is_integer() else round(avgs['C+H'], 2)
    
    for col in ['M', 'L', 'I', 'G']:
        avgs[col] = df[col].astype(int).mean()
        avgs[col] = int(avgs[col]) if avgs[col].is_integer() else round(avgs[col], 2)
    
    return avgs

def create_total_row(sums, num_rows):
    return f"|             | **Total**  |                                                                                           | _({num_rows} reports)_ | {sums['C']:>3} | {sums['H']:>3} | {sums['M']:>3} | {sums['L']:>3} | {sums['I']:>3} | {sums['G']:>3} |"

def create_averages_row(avgs):
    values = (
        f"**Average Findings Per Audit**<br>"
        f"* Crit/High {avgs['C+H']}<br>"
        f"* Medium {avgs['M']}<br>"
        f"* Low {avgs['L']}<br>"
        f"* Info {avgs['I']}<br>"
        f"* Gas {avgs['G']}"
    )
    return f"| {values} |"

def create_additional_table(df, heading):
    if heading == 'Staking':
        rows = df[df['Tech'].apply(lambda x: any('Staking' in tech and 'Liquid Staking' not in tech for tech in x.split(',')))]
    else:
        rows = df[df['Tech'].apply(lambda x: any(tech in x for tech in heading_tech_map[heading]))]
    
    if rows.empty:
        return ""
    
    table = "| Report                                                                                    | C   | H   | M   | L   | I   | G   |\n"
    table += "| ----------------------------------------------------------------------------------------- | --- | --- | --- | --- | --- | --- |\n"
    
    for _, row in rows.iterrows():
        table += f"| {row['Report']:<89} | {row['C']:>3} | {row['H']:>3} | {row['M']:>3} | {row['L']:>3} | {row['I']:>3} | {row['G']:>3} |\n"
    
    sums, num_rows = calculate_totals(rows)
    total_row_text = f"**Total** _({num_rows:d} reports)_".rstrip()
    padded_total_row = f"{total_row_text:<89}"
    table += f"| {padded_total_row} | {sums['C']:>3} | {sums['H']:>3} | {sums['M']:>3} | {sums['L']:>3} | {sums['I']:>3} | {sums['G']:>3} |\n"
    
    avgs = calculate_averages(rows)
    table += create_averages_row(avgs) + "\n"
    
    return table

def map_tech_to_headings():
    return {
        'Liquid Staking': ['Liquid Staking'],
        'CLM/DEX/AMM/Concentrated Liquidity': ['AMM', 'DEX', 'CLM', 'Concentrated'],
        'Cross-Chain / Wormhole / Chainlink CCIP / LayerZero / L2<->L1': ['Cross-Chain', 'Wormhole', 'CCIP', 'LayerZero', 'Layer Zero', 'L2'],
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
        df, content, table_end, newline_count, has_total_row, header = read_first_table_under_heading(file_path, 'Cyfrin Audit Reports')
        
        # Rebuild table from DataFrame with input-like formatting
        new_table = []
        new_table.append("| Audit Start | Audit End  | Report                                                                                    | Tech                | C   | H   | M   | L   | I   | G   |")
        new_table.append("| ----------- | ---------- | ----------------------------------------------------------------------------------------- | ------------------- | --- | --- | --- | --- | --- | --- |")
        for _, row in df.iterrows():
            formatted_row = [
                str(row['Audit Start']).ljust(11),
                str(row['Audit End']).ljust(10),
                str(row['Report']).ljust(89),
                str(row['Tech']).ljust(19),
                str(row['C']).rjust(3),
                str(row['H']).rjust(3),
                str(row['M']).rjust(3),
                str(row['L']).rjust(3),
                str(row['I']).rjust(3),
                str(row['G']).rjust(3)
            ]
            new_table.append("| " + " | ".join(formatted_row) + " |")
        
        # Calculate totals and append Total row
        sums, num_rows = calculate_totals(df)
        total_row = create_total_row(sums, num_rows)
        new_table.append(total_row)
        
        # Replace old table in content using regex
        header_pattern = r'\|\s*Audit Start\s*\|\s*Audit End\s*\|\s*Report\s*\|\s*Tech\s*\|\s*C\s*\|\s*H\s*\|\s*M\s*\|\s*L\s*\|\s*I\s*\|\s*G\s*\|'
        table_start_match = re.search(header_pattern, content)
        if not table_start_match:
            raise ValueError("Table header not found in content")
        table_start = table_start_match.start()
        old_table_end = content.find('\n\n## Legend', table_start)
        if old_table_end == -1:
            old_table_end = len(content)
        new_content = content[:table_start] + "\n".join(new_table) + "\n" * (newline_count + 1)
        
        # Find the end of the "## Legend" section
        legend_match = re.search(r'\n\n## Legend\n.*?(?=\n\n##|\Z)', content[table_end:], re.DOTALL)
        if legend_match:
            legend_end = table_end + legend_match.end()
            legend_content = legend_match.group(0)
        else:
            legend_end = len(content)
            legend_content = ""
        
        # Calculate report counts and AVG(C+H) for each heading
        heading_metrics = {}
        for heading in heading_tech_map.keys():
            if heading == 'Staking':
                rows = df[df['Tech'].apply(lambda x: any('Staking' in tech and 'Liquid Staking' not in tech for tech in x.split(',')))]
            else:
                rows = df[df['Tech'].apply(lambda x: any(tech in x for tech in heading_tech_map[heading]))]
            
            if not rows.empty:
                report_count = len(rows)
                avgs = calculate_averages(rows)
                heading_metrics[heading] = (report_count, avgs['C+H'])
            else:
                heading_metrics[heading] = (0, 0)
        
        # Sort headings
        sorted_headings = sorted(heading_tech_map.keys(), key=lambda h: (-heading_metrics[h][0], -heading_metrics[h][1], h))
        
        # Generate new additional tables
        additional_tables_content = ""
        generated_headings = set()
        for heading in sorted_headings:
            if heading in generated_headings:
                continue
            table_content = create_additional_table(df, heading)
            if table_content:
                formatted_heading = re.sub(r'\s*/\s*', ' / ', heading)
                additional_tables_content += f"\n\n## {formatted_heading}\n\n{table_content}"
                generated_headings.add(heading)
        
        # Preserve the "## Legend" section and append new tables
        new_content = new_content + legend_content + additional_tables_content
        
        # Save updated content
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content.rstrip() + '\n')
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    update_readme("README.md")