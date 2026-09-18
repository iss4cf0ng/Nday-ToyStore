import pandas as pd

df = pd.read_csv('rpc_database.csv')

result = df[df['function_name'].str.contains('PathCanonicalize', case=False, na=False)]

for index, row in result.iterrows():
    print(f"IDL file: {row['idl_name']}")
    print(f"Interface name: {row['interface_name']}")
    print(f"UUID: {row['interface_uuid']}")
    print(f"Version: {row['interface_version']}")
    print(f"Function name: {row['function_name']}")

    print("-" * 40)