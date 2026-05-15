# Storage Analyzer

Το **Storage Analyzer** είναι Windows desktop εργαλείο σε Python/Tkinter για έλεγχο χώρου ανά Windows user profile, εντοπισμό μεγάλων αρχείων και προαιρετική διαγραφή επιλεγμένων profiles από διαχειριστή.

## Κύριες δυνατότητες

- Σάρωση προεπιλεγμένου φακέλου `C:\Users` ή άλλου φακέλου που επιλέγει ο διαχειριστής.
- Υπολογισμός συνολικού μεγέθους ανά χρήστη.
- Ορατή στήλη `User / Username` στον πίνακα αποτελεσμάτων.
- Εντοπισμός μεγάλων αρχείων ανά χρήστη.
- Sorting με κλικ στα headers.
- Αριθμητικό/natural sorting για User/Username όταν είναι αριθμητικό μητρώο, καθώς και για bytes, αρχεία, φακέλους, σφάλματα και junction/symlink counters.
- Κεντραρισμένα headers και κεντραρισμένα αποτελέσματα/κελιά στους πίνακες.
- Χειροκίνητο export αποτελεσμάτων σε Excel `.xlsx`.
- Επιλογή profiles για διαγραφή με τικ στη στήλη **Διαγραφή**.
- Σταθερότερο checkbox διαγραφής με προστασία από άμεσο διπλό toggle σε γρήγορο δεύτερο click event.
- Διαγραφή μέσω native Python COM/WMI `Win32_UserProfile.Delete_()` χωρίς PowerShell.
- Εσωτερικό GUI panel **Αποτελέσματα διαγραφής** με ώρα, χρήστη, status, μήνυμα και SID.
- Καταγραφή αποτελεσμάτων διαγραφής σε `Deletion Log` μέσα στο Excel report.
- Μπλοκάρισμα τρέχοντος/προστατευμένου profile και μπλοκάρισμα profile που τα Windows εμφανίζουν ως `Loaded` ή `Special`.
- Αποφυγή junctions/symlinks/reparse points για περιορισμό διπλομετρήσεων και κύκλων.
- Συνέχιση σάρωσης ακόμα και όταν υπάρχουν `Access Denied` ή άλλα σφάλματα πρόσβασης.

## Ασφάλεια διαγραφής

Η σάρωση είναι μόνο ανάγνωση. Η διαγραφή γίνεται μόνο όταν ο διαχειριστής:

1. ολοκληρώσει σάρωση,
2. τικάρει συγκεκριμένα profiles,
3. πατήσει **Διαγραφή επιλεγμένων**,
4. επιβεβαιώσει το warning,
5. πληκτρολογήσει ακριβώς `DELETE`.

Το πρόγραμμα δεν κάνει απλή διαγραφή `C:\Users\username`. Χρησιμοποιεί Windows `Win32_UserProfile` μέσω Python COM/WMI ώστε να αφαιρεθεί το profile καθαρά μαζί με τα Windows profile metadata/registry entries.

## Απαιτήσεις source έκδοσης

- Windows 10 ή Windows 11
- Python 3.10+
- `openpyxl` για Excel export
- `pywin32` για native COM/WMI profile deletion

## Εκτέλεση από source

```bat
RUN_STORAGE_ANALYZER.bat
```

ή χειροκίνητα από Administrator CMD:

```bat
python -m pip install -r requirements.txt
python storage_analyzer.py
```

## Build σε EXE

```bat
build_exe.bat
```

Το τελικό αρχείο δημιουργείται στο:

```text
dist\StorageAnalyzer.exe
```

Για καθαρό build:

```bat
build_exe_clean.bat
```

## Περιεχόμενα release

- `storage_analyzer.py` - κύριο πρόγραμμα
- `requirements.txt` - source dependencies
- `requirements-build.txt` - build dependencies
- `StorageAnalyzer.spec` - PyInstaller spec με icon/UAC/metadata
- `version_info.txt` - Windows EXE metadata
- `app.ico` - εικονίδιο εφαρμογής
- `build_exe.bat` - build script
- `build_exe_clean.bat` - clean build script
- `RUN_STORAGE_ANALYZER.bat` - source runner
- `RUN_COMPILED_EXE_AS_ADMIN.bat` - runner για compiled EXE
