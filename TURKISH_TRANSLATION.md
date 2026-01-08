# Turkish Translation Guide

The Turkish (Türkçe) language infrastructure has been added to SoftEther VPN.

## Current Status

- ✅ Language entry added to `languages.txt` (ID: 8, identifier: `tr`)
- ✅ String table file created: `strtable_tr.stb`
- ✅ File structure validated with stbchecker
- ⚠️ **Translation needed**: The file currently contains English text as placeholders

## How to Contribute

The Turkish string table (`src/bin/hamcore/strtable_tr.stb`) currently uses English text. We need native Turkish speakers to translate these strings.

### Main Translation File

- **File**: `src/bin/hamcore/strtable_tr.stb` (~7,400 lines)
- **Format**: Each line has a KEY and a translatable value
- **Task**: Translate only the values, keep the keys unchanged
- **Note**: You can contribute partial translations - every bit helps!

### Quick Start

1. Fork this repository
2. Open `src/bin/hamcore/strtable_tr.stb`
3. Translate the text values (keep the keys unchanged)
4. Run the validation tool:
   ```bash
   cd developer_tools/stbchecker
   dotnet run ../../src/bin/hamcore
   ```
5. Submit a Pull Request with your translations

### Translation Guidelines

**Important Rules:**
- Keep technical terms like "VPN", "SSL", "TCP/IP", "IPsec" in English
- Preserve formatting codes like `%s`, `%d`, `\r\n` - they are placeholders
- Maintain the same meaning and tone as the English version
- Use formal Turkish ("siz" form) for user-facing messages
- Be consistent with terminology throughout

**Example Translation:**
```
# Original English:
ERR_1                   Connection to the server failed. Check network connection.

# Turkish translation:
ERR_1                   Sunucuya bağlantı başarısız oldu. Ağ bağlantısını kontrol edin.
```

**File Format:**
- Lines starting with `#` are comments (don't translate)
- Each entry: `STRING_KEY<tabs>Translated text here`
- Only translate the text after the key, never change the key itself

### Already Translated

The following metadata has been localized:
- Language identifier: Turkish
- Language ID: 8
- Weekday abbreviations: Paz, Pzt, Sal, Çar, Per, Cum, Cmt
- "None" translated to "Hiçbiri"

## Validation

Before submitting your translation, validate it with the consistency checker:

```bash
cd developer_tools/stbchecker
dotnet run ../../src/bin/hamcore
```

This ensures all string keys are present and the file format is correct. The validation must pass before submitting.

## Submitting Your Translation

1. Fork the SoftEther VPN repository on GitHub
2. Create a new branch: `git checkout -b turkish-translation`
3. Edit `src/bin/hamcore/strtable_tr.stb` with your translations
4. Validate your changes (see above)
5. Commit: `git commit -m "Add Turkish translations for [section]"`
6. Push to your fork: `git push origin turkish-translation`
7. Create a Pull Request on GitHub

**You can submit partial translations!** Translate the most important sections first:
- Error messages (ERR_*)
- Common UI strings (COMMON_*)
- Product names
- Menu items

## Questions?

If you have questions about the translation:
- Open an issue on GitHub
- Tag it with `translation` and `Turkish`

## Thank You!

Thank you to VamHunD and all contributors who help make SoftEther VPN accessible to Turkish users!
