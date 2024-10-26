import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from notion_client import Client
import datetime
import base64
from getpass import getpass
from dotenv import load_dotenv

class EncryptedJournal:
    BLOCK_CHAR_LIMIT = 2000
    MAX_BLOCKS_PER_REQUEST = 100
    
    def __init__(self, password):
        """Initialize the journal with Notion credentials and encryption key"""
        # Load environment variables
        load_dotenv()
        
        # Get Notion credentials from environment
        notion_token = os.getenv('NOTION_TOKEN')
        database_id = os.getenv('NOTION_JOURNAL_DATABASE_ID')
        
        if not notion_token:
            raise ValueError("Missing NOTION_TOKEN in environment variables")
        if not database_id:
            raise ValueError("Missing NOTION_JOURNAL_DATABASE_ID in environment variables")
        
        self.notion = Client(auth=notion_token)
        self.database_id = database_id
        
        # Generate encryption key from password
        self.salt = b'journal_salt_2024'
        self.setup_encryption(password)

    def setup_encryption(self, password):
        """Set up encryption using password-based key derivation"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

    def get_entry(self):
        """Get journal entry from user with a nice command-line interface"""
        print("\n=== New Journal Entry ===")
        print("Type your entry below (Press Ctrl+D on Unix/Linux or Ctrl+Z on Windows when finished):")
        print("----------------------------------------")
        
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        
        return "\n".join(lines)

    def encrypt_entry(self, text):
        """Encrypt the journal entry"""
        encrypted_data = self.cipher_suite.encrypt(text.encode())
        return base64.b64encode(encrypted_data).decode()

    def decrypt_entry(self, encrypted_text):
        """Decrypt the journal entry"""
        encrypted_data = base64.b64decode(encrypted_text.encode())
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        return decrypted_data.decode()

    def create_block_chunks(self, encrypted_text):
        """Split encrypted text into blocks that fit within Notion's limits"""
        chunks = []
        for i in range(0, len(encrypted_text), self.BLOCK_CHAR_LIMIT):
            chunk = encrypted_text[i:i + self.BLOCK_CHAR_LIMIT]
            chunks.append({
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": chunk
                            }
                        }
                    ]
                }
            })
        return chunks

    def save_to_notion(self, encrypted_text):
        """Save the encrypted entry to Notion as a page with content in blocks"""
        now = datetime.datetime.now()
        
        # First create the page with just the title
        new_page = self.notion.pages.create(
            parent={"database_id": self.database_id},
            properties={
                "Title": {"title": [{"text": {"content": f"Journal Entry - {now.strftime('%Y-%m-%d %H:%M')}"}}]}
            }
        )
        
        # Split content into blocks
        blocks = self.create_block_chunks(encrypted_text)
        total_blocks = len(blocks)
        
        # Add blocks in batches of MAX_BLOCKS_PER_REQUEST
        for i in range(0, total_blocks, self.MAX_BLOCKS_PER_REQUEST):
            batch = blocks[i:i + self.MAX_BLOCKS_PER_REQUEST]
            self.notion.blocks.children.append(
                new_page["id"],
                children=batch
            )
        
        return total_blocks

    def list_entries(self):
        """List all journal entries from the database"""
        response = self.notion.databases.query(
            database_id=self.database_id,
            sorts=[{
                "property": "Title",
                "direction": "descending"
            }]
        )
        
        entries = []
        for page in response.get('results', []):
            title = page['properties']['Title']['title'][0]['text']['content'] if page['properties']['Title']['title'] else "Untitled"
            entries.append({
                'id': page['id'],
                'title': title
            })
        
        return entries

    def read_entry(self, page_id):
        """Read and decrypt a journal entry"""
        # Get all blocks from the page
        blocks = []
        has_more = True
        start_cursor = None
        
        while has_more:
            if start_cursor:
                response = self.notion.blocks.children.list(
                    block_id=page_id,
                    start_cursor=start_cursor
                )
            else:
                response = self.notion.blocks.children.list(block_id=page_id)
            
            blocks.extend(response.get('results', []))
            has_more = response.get('has_more', False)
            start_cursor = response.get('next_cursor')

        # Combine all encrypted content from blocks
        encrypted_content = ''
        for block in blocks:
            if block['type'] == 'paragraph':
                rich_text = block['paragraph'].get('rich_text', [])
                if rich_text:
                    encrypted_content += rich_text[0]['text']['content']

        # Decrypt the combined content
        if encrypted_content:
            return self.decrypt_entry(encrypted_content)
        return None

def get_password():
    """Get password from user with confirmation"""
    while True:
        password = getpass("\nEnter your encryption password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            continue
            
        confirm = getpass("Confirm your encryption password: ")
        if password != confirm:
            print("Passwords don't match. Please try again.")
            continue
            
        return password

def main():
    try:
        print("Welcome to Encrypted Journal")
        print("============================")
        print("Your entries will be encrypted with your password.")
        print("Make sure to remember this password as it will be needed to decrypt your entries.")
        
        # Get password from user
        password = get_password()
        
        # Create journal instance with password
        journal = EncryptedJournal(password)
        
        while True:
            print("\nWhat would you like to do?")
            print("1. Write new entry")
            print("2. Read existing entry")
            print("3. Exit")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == "1":
                # Get the entry
                entry = journal.get_entry()
                
                if entry.strip():
                    # Encrypt and save
                    encrypted_entry = journal.encrypt_entry(entry)
                    total_blocks = journal.save_to_notion(encrypted_entry)
                    
                    print(f"\nJournal entry saved successfully using {total_blocks} blocks!")
                    if total_blocks > 1:
                        print(f"(Entry was split into multiple blocks due to length)")
                    
                    # Verify decryption works
                    decrypted = journal.decrypt_entry(encrypted_entry)
                    if decrypted == entry:
                        print("Encryption verification successful!")
                    else:
                        print("Warning: Encryption verification failed!")
                else:
                    print("\nNo entry provided.")
                    
            elif choice == "2":
                # List entries
                entries = journal.list_entries()
                if not entries:
                    print("\nNo entries found.")
                    continue
                
                print("\nAvailable entries:")
                for i, entry in enumerate(entries, 1):
                    print(f"{i}. {entry['title']}")
                
                try:
                    entry_num = int(input("\nEnter entry number to read (0 to cancel): "))
                    if entry_num == 0:
                        continue
                    if 1 <= entry_num <= len(entries):
                        entry_id = entries[entry_num - 1]['id']
                        decrypted_content = journal.read_entry(entry_id)
                        if decrypted_content:
                            print("\n=== Entry Content ===")
                            print(decrypted_content)
                            print("===================")
                        else:
                            print("\nNo content found in entry.")
                    else:
                        print("\nInvalid entry number.")
                except ValueError:
                    print("\nInvalid input.")
                    
            elif choice == "3":
                print("\nGoodbye!")
                break
            
            else:
                print("\nInvalid choice. Please try again.")
            
    except ValueError as ve:
        print(f"\nConfiguration Error: {str(ve)}")
        print("Please check your .env file and try again.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print("Please check your configuration and try again.")

if __name__ == "__main__":
    main()