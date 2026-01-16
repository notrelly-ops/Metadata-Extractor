Metadata Editor is a Python-based GUI tool for inspecting and editing printable strings inside binary and metadata files. It allows you to load executables, DLLs, or raw data files, automatically extract ASCII and UTF-16 strings, and view their exact file offsets and lengths.

The tool provides powerful filtering options, including search, minimum string length, hex preview mode, and a “modified only” view. Individual strings can be edited in-place with clear warnings when changes exceed the original length, and all modifications can be safely written back to the file in one operation.

Additional analysis features include basic file signature detection, pattern extraction for potential integers and floats, and lightweight data-type inspection (such as PE headers and null-byte density). Designed for reverse engineering, modding, and metadata exploration, this editor offers a practical balance between usability and low-level control.


<img width="1493" height="723" alt="metadataextractorpicture" src="https://github.com/user-attachments/assets/282cb64f-bc68-4b8c-85d0-d38ba372ac07" />
