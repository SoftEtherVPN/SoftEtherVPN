# Turkish Translation Status

The Turkish (Türkçe) language infrastructure has been added to SoftEther VPN.

## Current Status

- ✅ Language entry added to `languages.txt` (ID: 8, identifier: `tr`)
- ✅ String table file created: `strtable_tr.stb`
- ✅ File structure validated with stbchecker
- ⚠️ **Translation needed**: The file currently contains English text as placeholders

## How to Contribute

The Turkish string table (`src/bin/hamcore/strtable_tr.stb`) currently uses English text. We need native Turkish speakers to translate these strings.

### For Contributors

If you'd like to help with the Turkish translation:

1. See [TRANSLATION_GUIDE.md](TRANSLATION_GUIDE.md) for detailed instructions
2. The main file to translate is: `src/bin/hamcore/strtable_tr.stb`
3. It contains approximately 7,400+ lines, but many are comments or formatting
4. You can contribute partial translations - every bit helps!

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

- Keep technical terms like "VPN", "SSL", "TCP/IP" in English
- Preserve formatting codes like `%s`, `%d`, `\r\n`
- Maintain the same meaning and tone as the English version
- Use formal Turkish ("siz" form) for user-facing messages
- Be consistent with terminology throughout

### Already Translated

The following metadata has been localized:
- Language identifier: Turkish
- Language ID: 8
- Weekday abbreviations: Paz, Pzt, Sal, Çar, Per, Cum, Cmt
- "None" translated to "Hiçbiri"

## Questions?

If you have questions about the translation:
- Open an issue on GitHub
- Tag it with `translation` and `Turkish`
- Reference this file or the main TRANSLATION_GUIDE.md

## Thank You!

Thank you to VamHunD and all contributors who help make SoftEther VPN accessible to Turkish users!
