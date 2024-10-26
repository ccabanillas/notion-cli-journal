import os
from dotenv import load_dotenv
from notion_client import Client
import json

load_dotenv()

# Initialize the Notion client
notion = Client(auth=os.environ["NOTION_TOKEN"])

# Get the database ID from the .env file
database_id = os.environ["NOTION_JOURNAL_DATABASE_ID"]

def fetch_database_schema(database_id):
    try:
        # Retrieve the database
        database = notion.databases.retrieve(database_id)
        
        # Extract and format the schema
        schema = {}
        for prop_name, prop_info in database['properties'].items():
            schema[prop_name] = prop_info['type']
            
            # Add additional details for specific types
            if prop_info['type'] == 'select':
                schema[prop_name] = {
                    'type': 'select',
                    'options': [option['name'] for option in prop_info['select']['options']]
                }
            elif prop_info['type'] == 'multi_select':
                schema[prop_name] = {
                    'type': 'multi_select',
                    'options': [option['name'] for option in prop_info['multi_select']['options']]
                }
        
        return schema
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

# Fetch and print the schema
schema = fetch_database_schema(database_id)
if schema:
    print(json.dumps(schema, indent=2))
else:
    print("Failed to retrieve the database schema.")