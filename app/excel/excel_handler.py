import pandas as pd
import os

def excel_to_csv(input_path, output_dir):
    """
    input : Excel file
    output : CSV file
    """
    filename = os.path.basename(input_path)
    base_name, ext = os.path.splitext(filename)
    output_csv_path = os.path.join(output_dir, f"{base_name}.csv")

    if ext.lower() in ['.xlsx', '.xls']:
        df = pd.read_excel(input_path, dtype=str)
    elif ext.lower() == '.csv':
        df = pd.read_csv(input_path, dtype=str, encoding='utf-8-sig')
    else:
        raise ValueError(f"Unsupported file format: {ext}")

    # strip whitespace
    df = df.map(lambda x: x.strip() if isinstance(x, str) else x)
    
    df.to_csv(output_csv_path, index=False, encoding='utf-8-sig')
    return output_csv_path

def csv_to_excel(input_path, output_dir):
    """
    input : CSV file
    output : Excel file
    """
    filename = os.path.basename(input_path)
    base_name, ext = os.path.splitext(filename)
    output_excel_path = os.path.join(output_dir, f"{base_name}.xlsx")

    if ext.lower() == '.csv':
        df = pd.read_csv(input_path, dtype=str)
    else:
        raise ValueError(f"Unsupported file format: {ext}")

    # strip whitespace
    df = df.map(lambda x: x.strip() if isinstance(x, str) else x)

    df.to_excel(output_excel_path, index=False,engine = 'openpyxl')
    return output_excel_path
