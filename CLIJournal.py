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

# Configuration
SALT_LENGTH = 16
ITERATIONS = 100000  # Consider moving this to .env if you want it configurable

# Initialize Notion client
notion = Client(auth=os.getenv("NOTION_TOKEN"))

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"Salt must be {SALT_LENGTH} bytes long")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_entry(password: str, entry: str) -> tuple:
    if not entry:
        raise ValueError("Entry cannot be empty")
    
    salt = os.urandom(SALT_LENGTH)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_entry = f.encrypt(entry.encode())
    return salt + encrypted_entry

def decrypt_entry(password: str, encrypted_data: bytes) -> str:
    if len(encrypted_data) <= SALT_LENGTH:
        raise ValueError("Encrypted data is too short")
    
    salt, encrypted_entry = encrypted_data[:SALT_LENGTH], encrypted_data[SALT_LENGTH:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_entry).decode()

@click.group()
def cli():
    pass

@cli.command()
@click.option('--entry', prompt='Your journal entry', help='The journal entry to encrypt and upload.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for encryption.')
def add(entry, password):
    try:
        encrypted_data = encrypt_entry(password, entry)
        encrypted_entry_base64 = base64.b64encode(encrypted_data).decode()

        new_page = notion.pages.create(
            parent={"database_id": os.getenv("NOTION_DATABASE_ID")},
            properties={
                "Title": {"title": [{"text": {"content": f"Journal Entry - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}}]},
                "Content": {"rich_text": [{"text": {"content": encrypted_entry_base64}}]}
            }
        )

        click.echo(f'Entry added to Notion. Page ID: {new_page["id"]}')
    except ValueError as ve:
        click.echo(f"Validation error: {str(ve)}")
    except Exception as e:
        click.echo(f"An error occurred: {str(e)}")
        click.echo(traceback.format_exc())

@cli.command()
@click.option('--password', prompt=True, hide_input=True, help='Password for decryption.')
def list(password):
    try:
        pages = notion.databases.query(
            database_id=os.getenv("NOTION_DATABASE_ID"),
            sorts=[{"property": "Title", "direction": "descending"}]
        ).get("results")

        for page in pages:
            title = page["properties"]["Title"]["title"][0]["text"]["content"]
            encrypted_content_base64 = page["properties"]["Content"]["rich_text"][0]["text"]["content"]
            encrypted_content = base64.b64decode(encrypted_content_base64)
            
            try:
                decrypted_content = decrypt_entry(password, encrypted_content)
                click.echo(f"\n{title}")
                click.echo(f"Content: {decrypted_content[:50]}...")  # Show first 50 characters
                click.echo(f"Page ID: {page['id']}")
            except Exception as decrypt_error:
                click.echo(f"Failed to decrypt entry '{title}': {str(decrypt_error)}")

    except Exception as e:
        click.echo(f"An error occurred: {str(e)}")
        click.echo(traceback.format_exc())

@cli.command()
@click.option('--page-id', prompt='Page ID', help='The ID of the page to read.')
@click.option('--password', prompt=True, hide_input=True, help='Password for decryption.')
def read(page_id, password):
    try:
        page = notion.pages.retrieve(page_id=page_id)
        title = page["properties"]["Title"]["title"][0]["text"]["content"]
        encrypted_content_base64 = page["properties"]["Content"]["rich_text"][0]["text"]["content"]
        encrypted_content = base64.b64decode(encrypted_content_base64)
        
        decrypted_content = decrypt_entry(password, encrypted_content)
        
        click.echo(f"\n{title}")
        click.echo(f"Content:\n{decrypted_content}")

    except ValueError as ve:
        click.echo(f"Validation error: {str(ve)}")
    except Exception as e:
        click.echo(f"An error occurred: {str(e)}")
        click.echo(traceback.format_exc())

if __name__ == '__main__':
    cli()