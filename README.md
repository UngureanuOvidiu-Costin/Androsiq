# Androsiq

**Androsiq** is a lightweight Android forensics analysis tool designed to extract and present insights from common Android application data. It is inspired by tools like Oxygen Forensics Detective and Cellebrite but focuses only on data analysis, not acquisition.

## Features

- Accounts
- Calendar Events
- Call Logs
- Contacts
- SMS Messages
- Chrome Browser:
  - History
  - Downloads

## Planned Features

- Facebook Messenger chat history
- WhatsApp messages

## Usage

1. Extract relevant app data files (e.g. `/data/data/.../databases/`) from a device using your preferred acquisition method. (Known CVEs)
2. Run Androsiq on the extracted files.
3. View parsed data in a readable format.
**Note**: This tool, for the moment, assumes that you already have access to the necessary files. Androsiq does not perform device acquisition or bypass device protections.

## Requiremnts

- Python 3
- Tkinter

## License

MIT License
