import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox
import os
import struct
from collections import Counter
import re

class MetadataViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Metadata Editor")
        self.root.geometry("1100x700")
        
        self.filename = None
        self.original_data = None
        self.file_size = 0
        
        # Create main frames
        self.setup_main_frames()
        self.setup_file_info_panel()
        self.setup_control_panel()
        self.setup_listbox_panel()
        self.setup_edit_panel()
        self.setup_bottom_panel()
        
        self.configure_grid_weights()
        
        self.strings = []
        self.all_strings = []
        self.current_selection = None
        self.modified_strings = []
        
        # Settings
        self.min_string_length = 4
        self.show_hex = False
        self.show_only_modified = False
        
    def setup_main_frames(self):
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Left panel for file info and controls
        self.left_panel = ttk.Frame(self.main_frame, width=300)
        self.left_panel.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Right panel for list and edit
        self.right_panel = ttk.Frame(self.main_frame)
        self.right_panel.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def setup_file_info_panel(self):
        info_frame = ttk.LabelFrame(self.left_panel, text="File Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File load button
        self.load_btn = ttk.Button(info_frame, text="Load Metadata File", command=self.open_file)
        self.load_btn.pack(fill=tk.X, pady=(0, 10))
        
        # File info labels
        self.file_label = ttk.Label(info_frame, text="No file loaded", foreground="gray", wraplength=250)
        self.file_label.pack(anchor=tk.W)
        
        self.size_label = ttk.Label(info_frame, text="Size: --", foreground="gray")
        self.size_label.pack(anchor=tk.W)
        
        self.modified_label = ttk.Label(info_frame, text="Modified: 0 strings", foreground="blue")
        self.modified_label.pack(anchor=tk.W)
        
        # Separator
        ttk.Separator(info_frame, orient='horizontal').pack(fill=tk.X, pady=10)
        
        # File statistics
        stats_frame = ttk.Frame(info_frame)
        stats_frame.pack(fill=tk.X)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=8, width=30, 
                                                   font=("Consolas", 8), state='disabled')
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
    def setup_control_panel(self):
        control_frame = ttk.LabelFrame(self.left_panel, text="Filters & Options", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search
        ttk.Label(control_frame, text="Search:").pack(anchor=tk.W)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_strings)
        self.search_entry = ttk.Entry(control_frame, textvariable=self.search_var, state='disabled')
        self.search_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Minimum string length
        length_frame = ttk.Frame(control_frame)
        length_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(length_frame, text="Min Length:").pack(side=tk.LEFT)
        self.min_length_var = tk.StringVar(value="4")
        self.min_length_spin = ttk.Spinbox(length_frame, from_=1, to=100, width=8,
                                          textvariable=self.min_length_var,
                                          command=self.update_min_length)
        self.min_length_spin.pack(side=tk.RIGHT)
        
        # Checkbuttons
        self.hex_var = tk.BooleanVar(value=False)
        self.hex_check = ttk.Checkbutton(control_frame, text="Show Hex View", 
                                        variable=self.hex_var, command=self.toggle_hex_view)
        self.hex_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.modified_var = tk.BooleanVar(value=False)
        self.modified_check = ttk.Checkbutton(control_frame, text="Show Only Modified", 
                                             variable=self.modified_var, command=self.toggle_modified_view)
        self.modified_check.pack(anchor=tk.W)
        
        # Separator
        ttk.Separator(control_frame, orient='horizontal').pack(fill=tk.X, pady=10)
        
        # Additional metadata extraction
        ttk.Button(control_frame, text="Extract Patterns", 
                  command=self.extract_patterns).pack(fill=tk.X, pady=(0, 5))
        ttk.Button(control_frame, text="Find Data Types", 
                  command=self.find_data_types).pack(fill=tk.X)
        
    def setup_listbox_panel(self):
        list_frame = ttk.LabelFrame(self.right_panel, text="Strings Found", padding="10")
        list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Create listbox with scrollbar
        list_container = ttk.Frame(list_frame)
        list_container.pack(fill=tk.BOTH, expand=True)
        
        self.listbox = tk.Listbox(list_container, 
                                 font=("Consolas", 9),
                                 selectmode=tk.SINGLE,
                                 activestyle='none')
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_container, command=self.listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)
        
        self.listbox.bind('<<ListboxSelect>>', self.on_select)
        
        # Status label for listbox
        self.list_stats = ttk.Label(list_frame, text="No strings found")
        self.list_stats.pack(anchor=tk.W, pady=(5, 0))
        
    def setup_edit_panel(self):
        edit_frame = ttk.LabelFrame(self.right_panel, text="Edit String", padding="10")
        edit_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Info display
        info_frame = ttk.Frame(edit_frame)
        info_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.offset_label = ttk.Label(info_frame, text="Offset: --", font=("Consolas", 9))
        self.offset_label.pack(anchor=tk.W)
        
        self.length_label = ttk.Label(info_frame, text="Length: --", font=("Consolas", 9))
        self.length_label.pack(anchor=tk.W)
        
        # Text editor
        self.text_display = scrolledtext.ScrolledText(edit_frame, 
                                                     wrap=tk.WORD, 
                                                     font=("Consolas", 10),
                                                     height=15)
        self.text_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Button frame
        button_frame = ttk.Frame(edit_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.save_string_btn = ttk.Button(button_frame, text="Update String", 
                                         command=self.update_string, state='disabled')
        self.save_string_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.revert_btn = ttk.Button(button_frame, text="Revert", 
                                     command=self.revert_string, state='disabled')
        self.revert_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.save_all_btn = ttk.Button(button_frame, text="Save All Changes", 
                                       command=self.save_all_changes, state='disabled')
        self.save_all_btn.pack(side=tk.LEFT)
        
        # Warning label
        self.warning_label = ttk.Label(edit_frame, text="", foreground="red")
        self.warning_label.pack(anchor=tk.W, pady=(5, 0))
        
    def setup_bottom_panel(self):
        bottom_frame = ttk.Frame(self.main_frame)
        bottom_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_label = ttk.Label(bottom_frame, text="Ready - By NotRelly-ops on GitHub")
        self.status_label.pack(side=tk.LEFT)
        
    def configure_grid_weights(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        self.main_frame.columnconfigure(0, weight=0)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        
        self.right_panel.columnconfigure(0, weight=1)
        self.right_panel.columnconfigure(1, weight=1)
        self.right_panel.rowconfigure(0, weight=1)
        
    def open_file(self):
        filename = filedialog.askopenfilename(
            title="Select metadata file",
            filetypes=[("All files", "*.*"), ("Binary files", "*.bin;*.dat;*.meta"), 
                      ("Executables", "*.exe;*.dll;*.so"), ("Text files", "*.txt;*.json;*.xml")]
        )
        
        if filename:
            self.load_metadata(filename)
    
    def load_metadata(self, filename):
        try:
            with open(filename, 'rb') as f:
                self.original_data = bytearray(f.read())
            
            self.filename = filename
            self.file_size = len(self.original_data)
            
            # Update file info
            basename = os.path.basename(filename)
            self.file_label.config(text=f"File: {basename}", foreground="green")
            self.size_label.config(text=f"Size: {self.file_size:,} bytes")
            
            # Enable UI elements
            self.search_entry.config(state='normal')
            self.min_length_spin.config(state='normal')
            self.hex_check.config(state='normal')
            self.modified_check.config(state='normal')
            self.text_display.config(state='normal')
            self.save_all_btn.config(state='normal')
            
            # Extract strings and patterns
            self.extract_strings()
            self.update_file_stats()
            self.update_listbox()
            
            self.status_label.config(text=f"Loaded {filename} - {len(self.all_strings)} strings found")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def extract_strings(self):
        self.all_strings = []
        current_string = bytearray()
        string_start = None
        
        for i, byte in enumerate(self.original_data):
            if 32 <= byte <= 126:  # printable ASCII
                if len(current_string) == 0:
                    string_start = i
                current_string.append(byte)
            elif byte == 0:  # null terminator
                if len(current_string) >= self.min_string_length:
                    try:
                        string = current_string.decode('utf-8', errors='ignore')
                        if any(c.isprintable() for c in string):  # Only add if has printable chars
                            self.all_strings.append({
                                'offset': string_start,
                                'original': string,
                                'current': string,
                                'length': len(current_string),
                                'modified': False,
                                'type': 'ASCII'
                            })
                    except:
                        pass
                current_string = bytearray()
                string_start = None
            else:
                # For non-null terminated strings
                if len(current_string) >= self.min_string_length:
                    try:
                        string = current_string.decode('utf-8', errors='ignore')
                        if any(c.isprintable() for c in string):
                            self.all_strings.append({
                                'offset': string_start,
                                'original': string,
                                'current': string,
                                'length': len(current_string),
                                'modified': False,
                                'type': 'ASCII (no null)'
                            })
                    except:
                        pass
                current_string = bytearray()
                string_start = None
        
        # Check for any remaining string at end of file
        if len(current_string) >= self.min_string_length:
            try:
                string = current_string.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in string):
                    self.all_strings.append({
                        'offset': string_start,
                        'original': string,
                        'current': string,
                        'length': len(current_string),
                        'modified': False,
                        'type': 'ASCII (EOF)'
                    })
            except:
                pass
        
        self.strings = self.all_strings.copy()
        self.update_modified_count()
    
    def update_file_stats(self):
        if not self.original_data:
            return
            
        stats = []
        stats.append(f"File Size: {self.file_size:,} bytes")
        stats.append(f"Strings Found: {len(self.all_strings)}")
        
        # Count string types
        type_counter = Counter(s['type'] for s in self.all_strings)
        for type_name, count in type_counter.items():
            stats.append(f"  {type_name}: {count}")
        
        # Find potential file headers/signatures
        if len(self.original_data) >= 4:
            header = self.original_data[:4].hex().upper()
            stats.append(f"\nFirst 4 bytes: 0x{header}")
            
            # Check common file signatures
            signatures = {
                "MZ": "Windows EXE/DLL",
                "PK": "ZIP Archive",
                "%PDF": "PDF Document",
                "OggS": "Ogg Media",
                "ID3": "MP3 Audio",
                "GIF": "GIF Image",
                "PNG": "PNG Image",
                "JFIF": "JPEG Image"
            }
            
            file_start = self.original_data[:20].decode('ascii', errors='ignore')
            for sig, desc in signatures.items():
                if file_start.startswith(sig):
                    stats.append(f"Signature: {desc}")
                    break
        
        self.stats_text.config(state='normal')
        self.stats_text.delete('1.0', tk.END)
        self.stats_text.insert('1.0', '\n'.join(stats))
        self.stats_text.config(state='disabled')
    
    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        
        if not self.strings:
            self.list_stats.config(text="No strings found")
            return
        
        for idx, item in enumerate(self.strings):
            string = item['current']
            offset = item['offset']
            length = item['length']
            modified = item['modified']
            str_type = item.get('type', 'ASCII')
            
            # Create display string
            if self.show_hex:
                hex_preview = string[:30].encode('utf-8').hex()[:60]
                if len(string) > 30:
                    hex_preview += "..."
                display = f"[0x{offset:08X}] {hex_preview}"
            else:
                preview = string[:50]
                if len(string) > 50:
                    preview += "..."
                display = f"[0x{offset:08X}] {preview}"
            
            # Add markers
            if modified:
                display += " *MODIFIED*"
            if str_type != 'ASCII':
                display += f" ({str_type})"
            
            self.listbox.insert(tk.END, display)
            
            # Color modified items
            if modified:
                self.listbox.itemconfig(idx, {'fg': 'blue'})
            elif str_type != 'ASCII':
                self.listbox.itemconfig(idx, {'fg': 'darkgreen'})
        
        self.list_stats.config(text=f"Showing {len(self.strings)} of {len(self.all_strings)} strings")
    
    def filter_strings(self, *args):
        if not self.all_strings:
            return
        
        search_term = self.search_var.get().lower()
        min_length = int(self.min_length_var.get())
        
        filtered = []
        for item in self.all_strings:
            # Apply length filter
            if len(item['current']) < min_length:
                continue
            
            # Apply search filter
            if search_term and search_term not in item['current'].lower():
                continue
            
            # Apply modified filter
            if self.show_only_modified and not item['modified']:
                continue
            
            filtered.append(item)
        
        self.strings = filtered
        self.update_listbox()
    
    def update_min_length(self):
        try:
            self.min_string_length = int(self.min_length_var.get())
            if self.original_data:
                self.extract_strings()
                self.filter_strings()
        except ValueError:
            pass
    
    def toggle_hex_view(self):
        self.show_hex = self.hex_var.get()
        self.update_listbox()
    
    def toggle_modified_view(self):
        self.show_only_modified = self.modified_var.get()
        self.filter_strings()
    
    def on_select(self, event):
        selection = self.listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        if index < len(self.strings):
            self.current_selection = self.strings[index]
            
            # Update text display
            self.text_display.delete('1.0', tk.END)
            self.text_display.insert('1.0', self.current_selection['current'])
            
            # Update info labels
            offset = self.current_selection['offset']
            orig_len = self.current_selection['length']
            curr_len = len(self.current_selection['current'])
            str_type = self.current_selection.get('type', 'ASCII')
            
            self.offset_label.config(text=f"Offset: 0x{offset:08X} ({offset:,} dec)")
            self.length_label.config(text=f"Length: {curr_len} chars (Original: {orig_len}) Type: {str_type}")
            
            # Enable buttons
            self.save_string_btn.config(state='normal')
            self.revert_btn.config(state='normal')
            
            # Show warning if string is longer than original
            if curr_len > orig_len:
                self.warning_label.config(
                    text=f"WARNING: String is {curr_len - orig_len} characters longer than original!"
                )
            else:
                self.warning_label.config(text="")
    
    def update_string(self):
        if not self.current_selection or not self.filename:
            return
        
        new_text = self.text_display.get('1.0', 'end-1c')
        self.current_selection['current'] = new_text
        self.current_selection['modified'] = True
        
        # Update UI
        self.update_listbox()
        self.update_modified_count()
        self.status_label.config(text="String updated (not saved to file yet)")
    
    def revert_string(self):
        if not self.current_selection:
            return
        
        self.current_selection['current'] = self.current_selection['original']
        self.current_selection['modified'] = False
        
        # Update UI
        self.text_display.delete('1.0', tk.END)
        self.text_display.insert('1.0', self.current_selection['original'])
        self.update_listbox()
        self.update_modified_count()
        self.warning_label.config(text="")
        self.status_label.config(text="String reverted")
    
    def update_modified_count(self):
        self.modified_strings = [s for s in self.all_strings if s['modified']]
        count = len(self.modified_strings)
        self.modified_label.config(text=f"Modified: {count} string(s)")
    
    def save_all_changes(self):
        if not self.filename or not self.modified_strings:
            messagebox.showinfo("No Changes", "No strings have been modified.")
            return
        
        try:
            with open(self.filename, 'rb') as f:
                file_data = bytearray(f.read())
            
            # Sort by offset descending to avoid shifting issues
            sorted_strings = sorted(self.modified_strings, key=lambda x: x['offset'], reverse=True)
            
            for item in sorted_strings:
                offset = item['offset']
                original_bytes = item['original'].encode('utf-8') + b'\x00'
                new_bytes = item['current'].encode('utf-8') + b'\x00'
                
                # Replace bytes
                before = file_data[:offset]
                after = file_data[offset + len(original_bytes):]
                file_data = before + new_bytes + after
            
            # Write back to file
            with open(self.filename, 'wb') as f:
                f.write(file_data)
            
            # Reload to update offsets
            self.load_metadata(self.filename)
            
            messagebox.showinfo("Success", f"Saved {len(self.modified_strings)} string(s) to file.")
            self.status_label.config(text="All changes saved successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save changes: {str(e)}")
    
    def extract_patterns(self):
        if not self.original_data:
            return
        
        patterns = []
        
        # Look for potential 32-bit integers
        for i in range(0, len(self.original_data) - 3, 4):
            try:
                value = struct.unpack('<I', self.original_data[i:i+4])[0]
                if 0x1000 <= value <= 0xFFFFFFFF:  # Reasonable range for pointers/offsets
                    patterns.append(f"0x{i:08X}: DWORD 0x{value:08X} ({value:,})")
            except:
                pass
        
        # Look for potential floats
        for i in range(0, len(self.original_data) - 3, 4):
            try:
                value = struct.unpack('<f', self.original_data[i:i+4])[0]
                if abs(value) > 0.0001 and abs(value) < 1e10:  # Reasonable float range
                    patterns.append(f"0x{i:08X}: FLOAT {value:.6f}")
            except:
                pass
        
        # Show in a new window
        if patterns:
            self.show_patterns_window(patterns[:100])  # Limit to 100
        else:
            messagebox.showinfo("Patterns", "No significant patterns found.")
    
    def find_data_types(self):
        if not self.original_data:
            return
        
        data_info = []
        
        # Check for common file sections
        if len(self.original_data) > 100:
            # Analyze first 100 bytes
            header = self.original_data[:100]
            
            # Check for PE header
            if header[:2] == b'MZ':
                data_info.append("File Type: Windows PE (EXE/DLL)")
                # Try to find PE header offset
                if len(self.original_data) > 0x3C + 4:
                    pe_offset = struct.unpack('<I', self.original_data[0x3C:0x3C+4])[0]
                    if pe_offset + 4 < len(self.original_data):
                        if self.original_data[pe_offset:pe_offset+4] == b'PE\0\0':
                            data_info.append(f"PE Header at: 0x{pe_offset:08X}")
            
            # Count null bytes (potential padding)
            null_count = self.original_data.count(0)
            data_info.append(f"Null bytes: {null_count:,} ({null_count/len(self.original_data)*100:.1f}%)")
            
            # Check for UTF-16 strings
            utf16_strings = []
            i = 0
            while i < len(self.original_data) - 1:
                if self.original_data[i] == 0 and 32 <= self.original_data[i+1] <= 126:
                    # Potential UTF-16 LE string
                    start = i
                    while i < len(self.original_data) - 1 and self.original_data[i] == 0:
                        i += 2
                    length = (i - start) // 2
                    if length >= self.min_string_length:
                        try:
                            string = self.original_data[start:i].decode('utf-16-le', errors='ignore')
                            if any(c.isprintable() for c in string):
                                self.all_strings.append({
                                    'offset': start,
                                    'original': string,
                                    'current': string,
                                    'length': length,
                                    'modified': False,
                                    'type': 'UTF-16-LE'
                                })
                        except:
                            pass
                i += 1
            
            if any(s['type'] == 'UTF-16-LE' for s in self.all_strings):
                data_info.append("Found UTF-16 Little Endian strings")
        
        # Update display
        self.update_listbox()
        
        # Show data type info
        if data_info:
            self.stats_text.config(state='normal')
            self.stats_text.delete('1.0', tk.END)
            self.stats_text.insert('1.0', '\n'.join(data_info))
            self.stats_text.config(state='disabled')
    
    def show_patterns_window(self, patterns):
        window = tk.Toplevel(self.root)
        window.title("Extracted Patterns")
        window.geometry("600x400")
        
        text = scrolledtext.ScrolledText(window, font=("Consolas", 9))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text.insert('1.0', '\n'.join(patterns))
        text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = MetadataViewer(root)
    root.mainloop()