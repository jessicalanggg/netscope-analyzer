# NetScope v0.6: Model/View and background loading

- Packet rows use `QAbstractTableModel` rather than allocating seven `QTableWidgetItem`s per frame.
- `QSortFilterProxyModel` handles sorting and existing filter expressions. Frame numbers always refer to the original capture.
- A `QThread` reads and decodes PCAP records without blocking the Qt event loop. A busy indicator is shown during loading.
- Results are built off-thread, then committed on the GUI thread after the worker finishes. Invalid captures leave the previous capture intact.
- The GUI holds all raw packet bytes and decoded records in RAM. This release improves table memory overhead and loading responsiveness, **not** streaming or bounded-memory processing.
- Loading a second file is disabled until the current load finishes. Closing the window waits for cancellation at the next packet callback.
- The existing CLI and tests are unchanged. The Qt GUI must be compiled and tested on Windows with MSYS2 UCRT64 Qt 6.

## Known limitations / next steps

- PCAP parsing remains synchronous *within the worker*, and loading uses an indeterminate progress bar because the parser does not expose byte offsets.
- No incremental packet display during loading; packets appear after a successful load.
- Very large captures still require considerable RAM; consider packet indexing and on-demand byte retrieval for a future version.
- GUI smoke tests and a benchmark with 100k+ packets are recommended before making performance claims.
