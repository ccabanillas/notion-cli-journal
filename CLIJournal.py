import click
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from notion_client import Client
import os
from dotenv import load_dotenv
import base64
from datetime import datetime
import traceback

# Load environment variables
load_dotenv()

# Initialize Notion client
notion = Client(auth=os.getenv("NOTION_TOKEN"))

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'fixed_salt',  # In a real app, use a random salt and store it
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@click.group()
def cli():
    pass

@cli.command()
@click.option('--entry', prompt='Your journal entry', help='The journal entry to encrypt and upload.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for encryption.')
def add(entry, password):
    try:
        key = derive_key(password)
        f = Fernet(key)

        encrypted_entry = f.encrypt(entry.encode()).decode()

        new_page = notion.pages.create(
            parent={"database_id": os.getenv("NOTION_DATABASE_ID")},
            properties={
                "Title": {"title": [{"text": {"content": f"Journal Entry - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}}]},
                "Content": {"rich_text": [{"text": {"content": encrypted_entry}}]}
            }
        )

        click.echo(f'Entry added to Notion. Page ID: {new_page["id"]}')
    except Exception as e:
        click.echo(f"An error occurred: {str(e)}")

@cli.command()
@click.option('--password', prompt=True, hide_input=True, help='Password for decryption.')
def list(password):
    try:
        # Check if the NOTION_TOKEN is set
        if not os.getenv("NOTION_TOKEN"):
            raise ValueError("NOTION_TOKEN is not set in the environment variables.")

        # Check if the NOTION_DATABASE_ID is set
        if not os.getenv("NOTION_DATABASE_ID"):
            raise ValueError("NOTION_DATABASE_ID is not set in the environment variables.")

        key = derive_key(password)
        f = Fernet(key)

        pages = notion.databases.query(
            database_id=os.getenv("NOTION_DATABASE_ID"),
            sorts=[{"property": "Title", "direction": "descending"}]
        ).get("results")

        if not pages:
            click.echo("No entries found in the database.")
            return

        for page in pages:
            title = page["properties"]["Title"]["title"][0]["text"]["content"]
            encrypted_content = page["properties"]["Content"]["rich_text"][0]["text"]["content"]
            try:
                decrypted_content = f.decrypt(encrypted_content.encode()).decode()
            except Exception as decrypt_error:
                click.echo(f"Failed to decrypt entry '{title}': {str(decrypt_error)}")
                continue

            click.echo(f"\n{title}")
            click.echo(f"Content: {decrypted_content[:50]}...")  # Show first 50 characters
            click.echo(f"Page ID: {page['id']}")

    except ValueError as ve:
        click.echo(f"Configuration error: {str(ve)}")
    except Exception as e:
        click.echo(f"An error occurred: {str(e)}")
        click.echo("Detailed error information:")
        click.echo(traceback.format_exc())


@cli.command()
@click.option('--page-id', prompt='Page ID', help='The ID of the page to read.')
@click.option('--password', prompt=True, hide_input=True, help='Password for decryption.')
def read(page_id, password):
    try:
        key = derive_key(password)
        f = Fernet(key)

        page = notion.pages.retrieve(page_id=page_id)
        title = page["properties"]["Title"]["title"][0]["text"]["content"]
        encrypted_content = page["properties"]["Content"]["rich_text"][0]["text"]["content"]
        
        decrypted_content = f.decrypt(encrypted_content.encode()).decode()
        
        click.echo(f"\n{title}")
        click.echo(f"Content:\n{decrypted_content}")

    except Exception as e:
        click.echo(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    cli()