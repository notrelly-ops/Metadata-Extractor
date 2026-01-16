
# Metadata Editor

**Metadata Editor** is a Python Tkinter GUI tool for inspecting and editing strings in binary and metadata files. It automatically extracts ASCII and UTF-16 strings, shows their offsets and lengths, and lets you search, filter, and modify them. All changes can be saved back safely. Ideal for reverse engineering, modding, and exploring file data.

**Features:**

* Load binaries, executables, DLLs, and raw data files
* Extract and display ASCII and UTF-16 strings with offsets
* Search, filter by length, and view only modified strings
* Hex preview mode for low-level inspection
* Edit strings safely with warnings for length changes
* Pattern extraction for integers/floats and basic data-type analysis



<img width="1492" height="722" alt="metadataextpicture" src="https://github.com/user-attachments/assets/c1c42a22-fd51-458c-a94b-6978d03bb670" />




## How to Use

1. **Launch the application**
   Run `MetadataEditor.py` (requires Python 3 and Tkinter).

2. **Load a metadata file**
   Click **“Load Metadata File”** and select the file you want to inspect. The tool will automatically extract all printable strings.

3. **Browse strings**

   * Strings are listed on the right panel with their file offsets and lengths.
   * Use the **search box** or **minimum length filter** to find specific strings.
   * Enable **“Show Hex View”** to see a hexadecimal preview, or **“Show Only Modified”** to focus on edited strings.

4. **Edit strings**

   * Select a string from the list.
   * Modify its content in the **Edit String** panel.
   * Click **“Update String”** to mark it as modified.

5. **Revert changes (optional)**
   Click **“Revert”** to restore the original string if needed.

6. **Save all changes**
   Once you’re done editing, click **“Save All Changes”** to write your edits back to the file safely.

7. **Additional tools**

   * **Extract Patterns** – scans for potential integers and floats.
   * **Find Data Types** – analyzes the file for headers, null bytes, and UTF-16 strings.

