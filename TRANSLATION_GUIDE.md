# SoftEther VPN Translation Guide

This guide explains how to contribute translations to SoftEther VPN.

## Overview

SoftEther VPN supports multiple languages through string table (`.stb`) files. Each language has:
1. An entry in the language list file (`languages.txt`)
2. A complete string table file (`strtable_<lang>.stb`)

Currently supported languages:
- Japanese (ja)
- English (en)
- Simplified Chinese (cn)
- Traditional Chinese (tw)
- Korean (ko)
- Russian (ru)
- Portuguese-Brazil (pt_br)
- Indonesian (id)
- Turkish (tr)

## Adding a New Language

### Step 1: Add Language Entry

Edit `src/bin/hamcore/languages.txt` and add a new line with the following format:

```
<ID> <identifier> <English_Name> <Local_Name> <Windows_LCID> <UNIX_locales>
```

**Example (Turkish):**
```
8 tr Turkish Türkçe 1055 tr,tr_tr,turkish
```

**Fields explained:**
- **ID**: Sequential number (use the next available number)
- **identifier**: Short language code (e.g., `tr`, `de`, `fr`)
- **English_Name**: Language name in English (use underscores for spaces, e.g., `Simplified_Chinese`)
- **Local_Name**: Language name in its native script (e.g., `Türkçe`, `Deutsch`)
- **Windows_LCID**: Windows locale ID(s) - comma-separated if multiple (find your LCID at https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/)
- **UNIX_locales**: Comma-separated list of UNIX locale identifiers that should map to this language

### Step 2: Create String Table File

1. Copy the English string table as a template:
   ```bash
   cp src/bin/hamcore/strtable_en.stb src/bin/hamcore/strtable_<your_lang>.stb
   ```

2. Update the language metadata in your new file (lines 27-28):
   ```
   LANG                    <your_language_ID>
   LANGSTR                 <Your_Language_Name>
   ```

3. Update the `DEFAULT_LOCALE` parameter (line 22) with localized weekday abbreviations:
   ```
   DEFAULT_LOCALE          - - $ : : $ Sun Mon Tue Wed Thu Fri Sat : : : $ (None)
   ```
   Replace the weekday names and "(None)" with your language equivalents.

4. **Important**: Add the file to git using the `-f` flag (the hamcore directory is gitignored):
   ```bash
   git add -f src/bin/hamcore/strtable_<your_lang>.stb
   ```

### Step 3: Translate Strings

Translate all string entries in the file. Each entry follows the format:
```
STRING_KEY              Translated text here
```

**Important guidelines:**
- Keep the same `STRING_KEY` - only translate the value
- Preserve special formatting like `%s`, `%d`, `\r`, `\n` in the translations
- Some strings contain placeholders - maintain their order and format
- Technical terms (like "VPN", "SSL", "IPsec") are often kept in English
- Lines starting with `#` are comments and don't need translation

**Example:**
```
# Original English:
ERR_1                   Connection to the server failed. Check network connection.

# Turkish translation:
ERR_1                   Sunucuya bağlantı başarısız oldu. Ağ bağlantısını kontrol edin.
```

## Translation Workflow

### Best Practices

1. **Use a proper text editor** that supports UTF-8 encoding without BOM
2. **Translate in context** - understand what the UI looks like when possible
3. **Be consistent** - use the same translation for repeated terms
4. **Keep it concise** - UI space is limited
5. **Preserve formatting** - maintain line breaks, spacing, and special characters
6. **Test your work** - if possible, build and test the software with your translation

### Progressive Translation

You don't need to translate everything at once! You can:

1. Start with the most important strings (error messages, main UI elements)
2. Leave less critical strings in English temporarily
3. Submit incremental improvements via pull requests
4. Collaborate with other translators for your language

## Validating Your Translation

Before submitting, verify your translation passes the consistency checker:

```bash
cd developer_tools/stbchecker
dotnet run /path/to/SoftEtherVPN/src/bin/hamcore
```

This tool checks that:
- All string keys from other language files are present
- No extra or missing keys exist
- The file format is correct

**The checker must pass with "OK: Excellent! There are no errors" before submitting.**

## Submitting Your Translation

1. Fork the SoftEther VPN repository on GitHub
2. Create a new branch for your translation
3. Make your changes following the steps above
4. Commit your changes with a clear message:
   ```bash
   git commit -m "Add [Language] translation" 
   # or
   git commit -m "Update [Language] translation"
   ```
5. Push to your fork and create a Pull Request
6. In the PR description, mention:
   - Which language you've added/updated
   - Your native language proficiency
   - Any areas you'd like feedback on

## Getting Help

- **Questions about translation**: Open an issue on GitHub with the tag `translation`
- **Technical questions**: Refer to the main README.md
- **String context unclear**: Ask in your Pull Request or open an issue

## Special Notes

### Font Settings

Some languages may need specific fonts. Update these if needed (lines 18-21):
```
DEFAULT_FONT            Tahoma
DEFAULT_FONT_WIN7       Segoe UI
DEFAULT_FONT_2          Tahoma
DEFAULT_FONT_SIZE       8
```

### Character Encoding

All `.stb` files must be UTF-8 encoded. The system will automatically convert to the appropriate encoding for each platform.

### Regional Variants

For languages with significant regional differences (like Portuguese/Brazilian Portuguese), create separate entries:
- Use descriptive identifiers (e.g., `pt_br` vs `pt_pt`)
- Add both LCID codes if they differ
- Make the distinction clear in both English and local names

## Thank You!

Your translation helps make SoftEther VPN accessible to users worldwide. The community appreciates your contribution!
