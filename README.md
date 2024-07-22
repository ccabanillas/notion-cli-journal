# Notion Journal CLI

A command-line interface tool for maintaining an encrypted journal in Notion.

## Features

- Add encrypted journal entries to a Notion database
- List all entries
- Read and decrypt specific entries

## Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with your Notion token and database ID
4. Run the CLI tool: `python journal_cli.py`

## Usage

- Add an entry: `python journal_cli.py add`
- List entries: `python journal_cli.py list`
- Read an entry: `python journal_cli.py read`

## Security

All entries are encrypted before being stored in Notion. Keep your encryption password safe!