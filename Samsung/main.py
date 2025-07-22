#!/usr/bin/env python3
"""
Version 0.1
Samsung S22 Forensic Analysis Tool
A modern GUI application for analyzing Samsung S22 forensic data
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
import threading
from typing import Dict, List, Any, Optional


class ForensicDatabase:
    """Base class for database analysis"""    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db_name = os.path.basename(db_path)
        self.connection = None
        
    def connect(self) -> bool:
        """Connect to the database"""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            return True
        except sqlite3.Error as e:
            print(f"Error connecting to {self.db_name}: {e}")
            return False
            
    def disconnect(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            
    def get_tables(self) -> List[str]:
        """Get all table names in the database"""
        if not self.connection:
            return []
        cursor = self.connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        return [row[0] for row in cursor.fetchall()]
        
    def query(self, sql: str) -> List[Dict]:
        """Execute SQL query and return results with error handling for binary data"""
        if not self.connection:
            return []
        try:
            cursor = self.connection.cursor()
            cursor.execute(sql)
            results = []
            
            for row in cursor.fetchall():
                row_dict = {}
                for key in row.keys():
                    value = row[key]
                    # Handle binary/problematic data
                    if isinstance(value, bytes):
                        try:
                            # Try to decode as UTF-8
                            row_dict[key] = value.decode('utf-8')
                        except UnicodeDecodeError:
                            # If that fails, represent as hex or indicate binary data
                            if len(value) > 100:
                                row_dict[key] = f"<Binary data: {len(value)} bytes>"
                            else:
                                row_dict[key] = f"<Hex: {value.hex()[:50]}{'...' if len(value.hex()) > 50 else ''}>"
                    elif isinstance(value, str):
                        try:
                            # Verify the string is valid UTF-8
                            value.encode('utf-8')
                            row_dict[key] = value
                        except UnicodeEncodeError:
                            row_dict[key] = f"<Encoding error in text data>"
                    else:
                        row_dict[key] = value
                        
                results.append(row_dict)
            return results
            
        except sqlite3.Error as e:
            print(f"Query error in {self.db_name}: {e}")
            return []


class ContactsAnalyzer(ForensicDatabase):
    """Analyzer for contacts2.db"""    
    def get_contacts(self) -> List[Dict]:
        contacts_sql = """
        SELECT 
            raw_contacts._id AS contact_id,
            name_data.data1 AS name,
            phone_data.data1 AS phone_number
        FROM raw_contacts
        LEFT JOIN data AS name_data 
            ON name_data.raw_contact_id = raw_contacts._id 
            AND name_data.mimetype_id = (SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/name')
        LEFT JOIN data AS phone_data 
            ON phone_data.raw_contact_id = raw_contacts._id 
            AND phone_data.mimetype_id = (SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/phone_v2')
        ORDER BY name_data.data1
        """
        
        # Try the main query first
        results = self.query(contacts_sql)
        if results:
            return results
            
        # Fallback queries if the main one fails
        fallback_queries = [
            # Alternative with different mimetype format
            """
            SELECT 
                raw_contacts._id AS contact_id,
                name_data.data1 AS name,
                phone_data.data1 AS phone_number
            FROM raw_contacts
            LEFT JOIN data AS name_data 
                ON name_data.raw_contact_id = raw_contacts._id 
                AND name_data.mimetype_id = (SELECT _id FROM mimetypes WHERE mimetype LIKE '%name%')
            LEFT JOIN data AS phone_data 
                ON phone_data.raw_contact_id = raw_contacts._id 
                AND phone_data.mimetype_id = (SELECT _id FROM mimetypes WHERE mimetype LIKE '%phone%')
            ORDER BY name_data.data1
            LIMIT 1000
            """,
            # Simple fallback
            """
            SELECT 
                _id AS contact_id,
                display_name AS name,
                '' AS phone_number
            FROM raw_contacts
            WHERE display_name IS NOT NULL
            ORDER BY display_name
            LIMIT 1000
            """,
            # Generic data table query
            """
            SELECT 
                raw_contact_id AS contact_id,
                data1 AS name,
                data2 AS phone_number
            FROM data
            WHERE mimetype_id IN (SELECT _id FROM mimetypes WHERE mimetype LIKE '%name%' OR mimetype LIKE '%phone%')
            ORDER BY data1
            LIMIT 1000
            """
        ]
        
        for fallback_query in fallback_queries:
            try:
                results = self.query(fallback_query)
                if results:
                    return results
            except:
                continue
                
        return []


class CallLogAnalyzer(ForensicDatabase):
    """Analyzer for calllog.db"""    
    def get_call_history(self) -> List[Dict]:
        calls_sql = """
        SELECT number, type, date, duration, name, 
               CASE type 
                   WHEN 1 THEN 'Incoming'
                   WHEN 2 THEN 'Outgoing'
                   WHEN 3 THEN 'Missed'
                   ELSE 'Unknown'
               END as call_type
        FROM calls 
        ORDER BY date DESC
        """
        return self.query(calls_sql)


class MessagesAnalyzer(ForensicDatabase):
    """Analyzer for mmssms.db"""    
    def get_messages(self) -> List[Dict]:
        messages_sql = """
        SELECT address, body, date, type, read,
               CASE type
                   WHEN 1 THEN 'Received'
                   WHEN 2 THEN 'Sent'
                   ELSE 'Unknown'
               END as message_type
        FROM sms 
        ORDER BY date DESC
        LIMIT 1000
        """
        return self.query(messages_sql)


class BrowserAnalyzer(ForensicDatabase):
    """Analyzer for browser databases"""    
    def get_browsing_history(self) -> List[Dict]:
        # Try different common history table schemas
        possible_queries = [
            # Chrome-style history
            """
            SELECT url, title, visit_count as visits, last_visit_time as date,
                   CASE WHEN url IN (SELECT url FROM bookmarks) THEN 1 ELSE 0 END as bookmark
            FROM urls 
            WHERE url IS NOT NULL
            ORDER BY last_visit_time DESC
            LIMIT 1000
            """,
            # Alternative schema
            """
            SELECT url, title, visits, date, bookmark
            FROM bookmarks 
            WHERE url IS NOT NULL
            ORDER BY date DESC
            LIMIT 1000
            """,
            # Generic fallback - get first table with URL-like data
            """
            SELECT * FROM urls LIMIT 100
            """,
            # Another fallback
            """
            SELECT * FROM history LIMIT 100
            """
        ]
        
        for query in possible_queries:
            try:
                results = self.query(query)
                if results:
                    return results
            except:
                continue
                
        # If no specific queries work, try to find any table with URL data
        tables = self.get_tables()
        for table in tables:
            if any(keyword in table.lower() for keyword in ['url', 'history', 'visit', 'bookmark']):
                try:
                    results = self.query(f"SELECT * FROM {table} LIMIT 50")
                    if results and any('url' in str(key).lower() for key in results[0].keys() if results):
                        return results
                except:
                    continue
                    
        return []
        
    def get_chrome_downloads(self) -> List[Dict]:
        """Get downloads from Chrome History.db"""
        downloads_sql = """
        SELECT 
            downloads.id,
            downloads_url_chains.url,
            downloads.target_path,
            downloads.start_time,
            downloads.received_bytes,
            downloads.total_bytes,
            downloads.state,
            CASE downloads.state
                WHEN 1 THEN 'Complete'
                WHEN 2 THEN 'Cancelled'
                WHEN 3 THEN 'Interrupted'
                WHEN 4 THEN 'In Progress'
                ELSE 'Unknown'
            END as download_status
        FROM downloads
        JOIN downloads_url_chains 
            ON downloads.id = downloads_url_chains.id
        ORDER BY downloads.start_time DESC
        """
        return self.query(downloads_sql)
        
    def get_meta_data(self) -> List[Dict]:
        """Get metadata from Chrome History.db"""
        meta_sql = """
        SELECT key, value
        FROM meta
        """
        return self.query(meta_sql)


class CalendarAnalyzer(ForensicDatabase):
    """Analyzer for calendar.db"""    
    def get_events(self) -> List[Dict]:
        events_sql = """
        SELECT title, description, dtstart, dtend, 
               eventLocation, allDay
        FROM Events
        ORDER BY dtstart DESC
        LIMIT 500
        """
        return self.query(events_sql)


class AccountsAnalyzer(ForensicDatabase):
    """Analyzer for accounts.db"""
    def get_accounts(self) -> List[Dict]:
        accounts_sql = """
        SELECT 
            name, 
            type, 
            password 
        FROM accounts
        ORDER BY type, name
        """
        
        results = self.query(accounts_sql)
        if results:
            return results
        
        # Fallback if structure is different
        fallback_queries = [
            """
            SELECT * FROM accounts LIMIT 100
            """,
            """
            SELECT a.name, a.type, at.authtoken 
            FROM accounts a 
            LEFT JOIN authtokens at ON a._id = at.accounts_id
            LIMIT 100
            """,
        ]
        
        for q in fallback_queries:
            try:
                res = self.query(q)
                if res:
                    return res
            except:
                continue
        
        return []


class ForensicApp:
    """Main application class"""    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Samsung S22 Forensic Analysis Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1a1a1a')
        
        # Style configuration
        self.setup_styles()
        
        # Data storage
        self.loaded_databases = {}
        self.current_data = []
        
        # Create GUI
        self.create_gui()
        
    def setup_styles(self):
        """Configure modern dark theme styles"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors for dark theme
        self.style.configure('TFrame', background='#1a1a1a')
        self.style.configure('TLabel', background='#1a1a1a', foreground='#ffffff', font=('Segoe UI', 10))
        self.style.configure('TButton', background='#2d2d2d', foreground='#ffffff', 
                           borderwidth=0, focuscolor='none', font=('Segoe UI', 10))
        self.style.map('TButton', background=[('active', '#3d3d3d'), ('pressed', '#1d1d1d')])
        
        self.style.configure('Treeview', background='#2d2d2d', foreground='#ffffff',
                           fieldbackground='#2d2d2d', borderwidth=0, font=('Segoe UI', 9))
        self.style.configure('Treeview.Heading', background='#3d3d3d', foreground='#ffffff',
                           borderwidth=0, font=('Segoe UI', 10, 'bold'))
        
        self.style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff',
                           padding=[20, 10], borderwidth=0, font=('Segoe UI', 10))
        self.style.map('TNotebook.Tab', background=[('selected', '#3d3d3d')])
        
    def create_gui(self):
        """Create the main GUI interface"""
        # Header frame
        header_frame = tk.Frame(self.root, bg='#0d1117', height=80)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(header_frame, text="Samsung S22 Forensic Analysis", 
                              font=('Segoe UI', 24, 'bold'), bg='#0d1117', fg='#58a6ff')
        title_label.pack(side='left', padx=20, pady=20)
        
        # Subtitle
        subtitle_label = tk.Label(header_frame, text="AAC Mobile Forensics Tool", 
                                 font=('Segoe UI', 12), bg='#0d1117', fg='#8b949e')
        subtitle_label.pack(side='left', padx=(0, 20), pady=(30, 10))
        
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Left panel - Database selection
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        
        # Database selection frame
        db_frame = tk.Frame(left_panel, bg='#2d2d2d', relief='flat', bd=1)
        db_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        tk.Label(db_frame, text="Database Files", font=('Segoe UI', 14, 'bold'),
                bg='#2d2d2d', fg='#ffffff').pack(pady=10)
        
        # Database buttons
        self.db_buttons = {}
        db_types = [
            ("Contacts", "contacts2.db"),
            ("Call Log", "calllog.db"),
            ("Messages", "mmssms.db"),
            ("Chrome History", "chrome_history.db"),
            ("Chrome Downloads", "chrome_downloads"),
            ("Calendar", "calendar.db"),
            ("Facebook Messenger", "threads_db2.db"),
            ("WhatsApp", "whatsapp_messages"),
            ("Skype Calls", "skype_calls"),
            ("WiFi Passwords", "wifi_passwords"),
            ("Accounts", "accounts.db")
        ]
        
        for db_name, db_file in db_types:
            btn_frame = tk.Frame(db_frame, bg='#2d2d2d')
            btn_frame.pack(fill='x', padx=10, pady=2)
            
            btn = tk.Button(btn_frame, text=f"Load {db_name}", 
                           command=lambda f=db_file, n=db_name: self.load_database(f, n),
                           bg='#3d3d3d', fg='#ffffff', relief='flat', bd=0,
                           font=('Segoe UI', 10), pady=8)
            btn.pack(side='left', fill='x', expand=True)
            
            status_label = tk.Label(btn_frame, text="○", bg='#2d2d2d', fg='#6e7681',
                                  font=('Segoe UI', 12))
            status_label.pack(side='right', padx=5)
            
            self.db_buttons[db_file] = (btn, status_label)
            
        # Right panel - Data display
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_tabs()
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#0d1117', height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Ready", bg='#0d1117', fg='#8b949e',
                                    font=('Segoe UI', 10))
        self.status_label.pack(side='left', padx=10, pady=5)
        
    def create_tabs(self):
        """Create tabbed interface for different data views"""
        # Overview tab
        overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(overview_frame, text="Overview")
        
        self.overview_text = tk.Text(overview_frame, bg='#2d2d2d', fg='#ffffff',
                                    font=('Consolas', 10), relief='flat', bd=0)
        overview_scroll = ttk.Scrollbar(overview_frame, orient='vertical', command=self.overview_text.yview)
        self.overview_text.configure(yscrollcommand=overview_scroll.set)
        
        self.overview_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        overview_scroll.pack(side='right', fill='y')
        
        # Data table tab
        table_frame = ttk.Frame(self.notebook)
        self.notebook.add(table_frame, text="Data Table")
        
        # Create treeview for data display
        self.tree = ttk.Treeview(table_frame)
        tree_scroll_y = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(table_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        self.tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        tree_scroll_y.pack(side='right', fill='y')
        tree_scroll_x.pack(side='bottom', fill='x')
        
        # Timeline tab
        timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(timeline_frame, text="Timeline")
        
        self.timeline_text = tk.Text(timeline_frame, bg='#2d2d2d', fg='#ffffff',
                                    font=('Consolas', 10), relief='flat', bd=0)
        timeline_scroll = ttk.Scrollbar(timeline_frame, orient='vertical', command=self.timeline_text.yview)
        self.timeline_text.configure(yscrollcommand=timeline_scroll.set)
        
        self.timeline_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        timeline_scroll.pack(side='right', fill='y')
        
        # Export tab
        export_frame = ttk.Frame(self.notebook)
        self.notebook.add(export_frame, text="Export")
        
        export_btn = ttk.Button(export_frame, text="Export to JSON", command=self.export_data)
        export_btn.pack(pady=20)
        
        # Initialize overview
        self.update_overview()
        
    def load_database(self, db_file: str, db_name: str):
        """Load a database file"""
        # Special handling for Chrome History.db that contains multiple data types
        if db_file in ['chrome_downloads', 'chrome_meta']:
            title = f"Select Chrome History.db file for {db_name}"
            filetypes = [("Chrome History", "History.db"), ("SQLite databases", "*.db"), ("All files", "*.*")]
        else:
            title = f"Select {db_name} database file"
            filetypes = [("SQLite databases", "*.db"), ("All files", "*.*")]
        
        file_path = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes
        )
        
        if not file_path:
            return
            
        self.status_label.config(text=f"Loading {db_name}...")
        
        # Run in thread to avoid blocking UI
        thread = threading.Thread(target=self._load_database_thread, 
                                 args=(file_path, db_file, db_name))
        thread.daemon = True
        thread.start()
        
    def _load_database_thread(self, file_path: str, db_file: str, db_name: str):
        """Load database in separate thread"""
        try:
            # Create appropriate analyzer
            if 'contacts' in db_file.lower():
                analyzer = ContactsAnalyzer(file_path)
                if analyzer.connect():
                    data = analyzer.get_contacts()
                    self._update_ui_after_load(db_file, db_name, data, 'contacts')
            elif 'calllog' in db_file.lower():
                analyzer = CallLogAnalyzer(file_path)
                if analyzer.connect():
                    data = analyzer.get_call_history()
                    self._update_ui_after_load(db_file, db_name, data, 'calls')
            elif 'mmssms' in db_file.lower():
                analyzer = MessagesAnalyzer(file_path)
                if analyzer.connect():
                    data = analyzer.get_messages()
                    self._update_ui_after_load(db_file, db_name, data, 'messages')
            elif 'browser' in db_file.lower() or 'chrome' in db_file.lower():
                analyzer = BrowserAnalyzer(file_path)
                if analyzer.connect():
                    if 'downloads' in db_file.lower():
                        data = analyzer.get_chrome_downloads()
                        self._update_ui_after_load(db_file, db_name, data, 'downloads')
                    elif 'meta' in db_file.lower():
                        data = analyzer.get_meta_data()
                        self._update_ui_after_load(db_file, db_name, data, 'meta')
                    else:
                        data = analyzer.get_browsing_history()
                        self._update_ui_after_load(db_file, db_name, data, 'browser')
            elif 'calendar' in db_file.lower():
                analyzer = CalendarAnalyzer(file_path)
                if analyzer.connect():
                    data = analyzer.get_events()
                    self._update_ui_after_load(db_file, db_name, data, 'calendar')
            elif 'accounts' in db_file.lower():     
                analyzer = AccountsAnalyzer(file_path)
                if analyzer.connect():
                    data = analyzer.get_accounts()
                    self._update_ui_after_load(db_file, db_name, data, 'accounts')
            else:
                # Generic database handler
                analyzer = ForensicDatabase(file_path)
                if analyzer.connect():
                    tables = analyzer.get_tables()
                    if tables:
                        # Get data from first table as sample
                        data = analyzer.query(f"SELECT * FROM {tables[0]} LIMIT 100")
                        self._update_ui_after_load(db_file, db_name, data, 'generic')
                        
            analyzer.disconnect()
            
        except Exception as e:
            self.root.after(0, lambda: self.status_label.config(text=f"Error loading {db_name}: {str(e)}"))
            
    def _update_ui_after_load(self, db_file: str, db_name: str, data: List[Dict], data_type: str):
        """Update UI after successful database load"""
        def update():
            # Update button status
            if db_file in self.db_buttons:
                btn, status_label = self.db_buttons[db_file]
                status_label.config(text="●", fg='#26a641')
                
            # Store data
            self.loaded_databases[db_name] = {
                'data': data,
                'type': data_type,
                'count': len(data)
            }
            
            # Update displays
            self.update_data_table(data)
            self.update_overview()
            self.update_timeline()
            
            self.status_label.config(text=f"Loaded {db_name}: {len(data)} records")
            
        self.root.after(0, update)
        
    def update_data_table(self, data: List[Dict]):
        """Update the data table with new data"""
        # Clear existing data
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        if not data:
            return
            
        # Configure columns
        columns = list(data[0].keys())
        self.tree['columns'] = columns
        self.tree['show'] = 'headings'
        
        # Configure column headings and widths
        for col in columns:
            self.tree.heading(col, text=col.replace('_', ' ').title())
            self.tree.column(col, width=120, minwidth=80)
            
        # Insert data
        for item in data[:1000]:  # Limit to first 1000 records for performance
            values = [str(item.get(col, '')) for col in columns]
            self.tree.insert('', 'end', values=values)
            
    def update_overview(self):
        """Update overview tab"""
        self.overview_text.delete(1.0, tk.END)
        
        overview = "=== SAMSUNG S22 FORENSIC ANALYSIS OVERVIEW ===\n\n"
        overview += f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        overview += f"Loaded Databases: {len(self.loaded_databases)}\n\n"
        
        if self.loaded_databases:
            overview += "Database Summary:\n"
            overview += "-" * 50 + "\n"
            
            for db_name, info in self.loaded_databases.items():
                overview += f"{db_name:<20}: {info['count']} records\n"
                
            overview += "\nDetailed Information:\n"
            overview += "=" * 50 + "\n"
            
            for db_name, info in self.loaded_databases.items():
                overview += f"\n{db_name.upper()}:\n"
                overview += f"  Records: {info['count']}\n"
                overview += f"  Type: {info['type']}\n"
                
                if info['data']:
                    sample = info['data'][0]
                    overview += f"  Sample fields: {', '.join(list(sample.keys())[:5])}\n"
        else:
            overview += "No databases loaded yet.\n"
            overview += "Use the buttons on the left to load database files.\n"
            
        self.overview_text.insert(tk.END, overview)
        
    def update_timeline(self):
        """Update timeline tab"""
        self.timeline_text.delete(1.0, tk.END)
        
        timeline_events = []
        
        # Collect timeline events from all databases
        for db_name, info in self.loaded_databases.items():
            data = info['data']
            
            for record in data[:100]:  # Limit for performance
                # Extract timestamp fields
                timestamp = None
                event_desc = ""
                
                if 'date' in record:
                    timestamp = record.get('date')
                    if info['type'] == 'calls':
                        event_desc = f"Call: {record.get('call_type', 'Unknown')} - {record.get('number', 'Unknown')}"
                    elif info['type'] == 'messages':
                        event_desc = f"SMS: {record.get('message_type', 'Unknown')} - {record.get('address', 'Unknown')}"
                elif 'dtstart' in record:
                    timestamp = record.get('dtstart')
                    event_desc = f"Calendar: {record.get('title', 'No title')}"
                elif 'lastmod' in record:
                    timestamp = record.get('lastmod')
                    event_desc = f"Download: {record.get('title', 'Unknown file')}"
                elif 'start_time' in record:
                    timestamp = record.get('start_time')
                    event_desc = f"Download: {record.get('target_path', record.get('url', 'Unknown file'))} ({record.get('download_status', 'Unknown')})"
                    
                if timestamp:
                    try:
                        # Convert timestamp to readable format
                        if isinstance(timestamp, (int, float)):
                            if timestamp > 1000000000000:  # Milliseconds
                                timestamp = timestamp / 1000
                            dt = datetime.fromtimestamp(timestamp)
                        else:
                            dt = datetime.fromisoformat(str(timestamp).replace('Z', ''))
                            
                        timeline_events.append((dt, event_desc, db_name))
                    except:
                        continue
                        
        # Sort events by time
        timeline_events.sort(key=lambda x: x[0], reverse=True)
        
        timeline = "=== FORENSIC TIMELINE ===\n\n"
        
        if timeline_events:
            for dt, event, source in timeline_events[:200]:  # Show latest 200 events
                timeline += f"{dt.strftime('%Y-%m-%d %H:%M:%S')} | {source:<15} | {event}\n"
        else:
            timeline += "No timeline data available.\n"
            timeline += "Load databases with timestamp information to see timeline events.\n"
            
        self.timeline_text.insert(tk.END, timeline)
        
    def export_data(self):
        """Export loaded data to JSON file"""
        if not self.loaded_databases:
            messagebox.showwarning("No Data", "No databases loaded to export.")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Forensic Data",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                export_data = {
                    'export_date': datetime.now().isoformat(),
                    'device_info': 'Samsung Galaxy S22',
                    'databases': {}
                }
                
                for db_name, info in self.loaded_databases.items():
                    export_data['databases'][db_name] = {
                        'record_count': info['count'],
                        'data_type': info['type'],
                        'records': info['data'][:500]  # Limit to 500 records per database
                    }
                    
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, default=str)
                    
                messagebox.showinfo("Export Complete", f"Data exported successfully to:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")
                
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ForensicApp()
    app.run()
