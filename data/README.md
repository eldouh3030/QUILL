# Data

| File | Source | Licence |
|---|---|---|
| `100.dat`, `100.hea` | MIT-BIH Arrhythmia Database, record 100 (PhysioNet, Moody and Mark 2001) | Open Data Commons Attribution 1.0 |
| `vitals.csv` | MIMIC-II/III Waveform Database Matched Subset, minute numerics of records s00001 and s25047 as redistributed in the WFDB sample data (MIT-LCP/wfdb-python, `sample-data/multi-segment`); 1611 records of HR, SpO2, SYS, DIA, RESP | PhysioNet open access, de-identified |

The ECG stream uses lead MLII at 360 Hz, 64 samples per packet packed as 12-bit values (96-byte
payload). The vital-sign stream replays one record per second (16-byte payload); a record is
urgent when HR < 40 or > 130 /min, SpO2 < 90 % or RESP < 8 or > 30 /min (20 of 1611 records).

Goldberger AL et al. PhysioBank, PhysioToolkit, and PhysioNet. Circulation 101(23):e215-e220, 2000.
Moody GB, Mark RG. The impact of the MIT-BIH Arrhythmia Database. IEEE EMB Magazine 20(3):45-50, 2001.
